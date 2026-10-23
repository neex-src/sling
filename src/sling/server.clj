(ns sling.server
  "The fake tenant: the same URLs the real one has, on one port, so a service, a lambda, a browser
  or Frodo can be pointed at it by changing a base URL and nothing else.

    journeys  POST .../authenticate[?authIndexType=service&authIndexValue=<journey>]   the callback loop
              GET|PUT .../realm-config/authentication/authenticationtrees/trees[/<name>]
              GET|PUT .../realm-config/authentication/authenticationtrees/nodes/<type>/<version>/<id>
              GET|PUT .../scripts[/<uuid>]                                       source is base64
    oauth     /am/oauth2[/realms/root/realms/<r>]/...          see sling.oauth
    idm       /openidm/managed/<type>[/<id>]                    see sling.idm
    am        /am/json/serverinfo/*, .../sessions, /am/XUI/     see sling.am
    esv       /environment/variables, /environment/secrets      see sling.am

  Each group is a module; start with only the ones a consumer needs ({:modules #{:oauth}}) and a
  call into a module that is off answers 404 and names it, so a hidden dependency shows at once.

  The tenant is read from a sling directory (tenant/, PUTs write the files back, so `git diff`
  shows what a deploy changed) or from a Frodo export ({:frodo dir}, PUTs stay in memory).
  Management calls need a token with fr:am:* (or fr:idm:* for /openidm), an SSO session, or the
  dev token. Send `X-Sling-Debug: true` on /authenticate to get the reason and the node trace.

  Usage: clojure -M -m sling.server [port] [tenant-dir]   (bb serve)"
  (:require [cheshire.core :as json]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [sling.am :as am]
            [sling.engine :as engine]
            [sling.frodo :as frodo]
            [sling.idm :as idm]
            [sling.jwt :as jwt]
            [sling.oauth :as oauth]
            [sling.store :as store]
            [sling.web :as web])
  (:import (com.sun.net.httpserver HttpExchange HttpHandler HttpServer)
           (java.net InetSocketAddress)
           (java.util Base64 UUID)))

(def all-modules #{:journeys :oauth :idm :am :esv})

;; ---- authorization of management calls ----------------------------------------------------

(defn- allowed? [srv req scope]
  (let [tok (web/bearer req)
        claims (some->> tok (oauth/token-claims srv))]
    (boolean (or (and tok (= tok (get-in srv [:opts :dev-token])))
                 (contains? (oauth/scopes-of claims) scope)
                 (oauth/sso-session srv req)
                 (some-> (web/header req "iplanetdirectorypro") (#(get @(:sso srv) %)))))))

(defn- deny [srv req]
  (if (or (web/bearer req) (web/header req "authorization"))
    (web/error 403 "token lacks the scope this endpoint needs")
    (web/error 401 "Access Denied")))

;; ---- journeys ------------------------------------------------------------------------------

(defn- sso-from
  "Turn a finished journey into an SSO session and its cookie."
  [{:keys [sso idm opts]} realm session]
  (let [id (str "AQIC" (str/replace (str (UUID/randomUUID)) "-" ""))
        username (get-in session [:shared "username"])
        user (when username (idm/find-by idm (str realm "_user") :userName username))]
    (swap! sso assoc id {:username username :user-id (or (:_id user) username) :user user :realm realm
                         :props (:props session) :auth-time (jwt/now)})
    [id (str (:cookie-name opts) "=" id "; Path=/; HttpOnly; SameSite=Lax")]))

(defn- authenticate [{:keys [tenant sessions] :as srv} req realm]
  (let [t @tenant
        debug? (= "true" (web/header req "x-sling-debug"))
        in (web/json-body req)
        journey (if (= "service" (web/param req "authIndexType"))
                  (web/param req "authIndexValue")
                  (or (get-in t [:services :default-journey]) "Login"))
        res (if (:authId in)
              (if-let [s (get @sessions (:authId in))]
                (engine/resume t s (:callbacks in))
                {:status :failure :reason "unknown or expired authId" :session nil})
              (engine/start t journey {:headers (:headers req) :parameters (:query req) :cookies (web/cookies req)}))
        dbg (when debug? {:_sling {:reason (:reason res) :trace (get-in res [:session :trace])
                                        :sessionProperties (get-in res [:session :props])}})]
    (when (and (:authId in) (not= :callbacks (:status res))) (swap! sessions dissoc (:authId in)))
    (case (:status res)
      :callbacks (let [id (str (UUID/randomUUID))]
                   (swap! sessions assoc id (:session res))
                   (web/json 200 (merge {:authId id :callbacks (:callbacks res)} dbg)))
      :success (let [[id cookie] (sso-from srv realm (:session res))]
                 (assoc-in (web/json 200 (merge {:tokenId id :successUrl (str "/enduser/?realm=/" realm)
                                                 :realm (str "/" realm)} dbg))
                           [:headers "Set-Cookie"] [cookie]))
      (web/json 401 (merge {:code 401 :reason "Unauthorized" :message "Login failure"} dbg)))))

(defn- reload! [{:keys [tenant dir realm]}]
  (swap! tenant (fn [old] (merge (store/load-tenant dir realm) (select-keys old [:services :clients])))))

(defn- decode-script [{:keys [script] :as body}]
  {:meta (dissoc body :script) :source (String. (.decode (Base64/getDecoder) ^String script) "UTF-8")})

(defn- manage [{:keys [tenant dir opts] :as srv} req realm kind args]
  (let [m (:method req)
        files? (and dir (not (:frodo opts)))
        t @tenant]
    (case [kind m]
      [:trees "GET"] (if-let [name (first args)]
                       (if-let [tree (get-in t [:trees name])]
                         (web/json 200 (assoc tree :_rev "0"))
                         (web/error 404 (str "Tree " name " not found")))
                       (web/json 200 {:result (vec (vals (:trees t))) :resultCount (count (:trees t))}))
      [:trees "PUT"] (let [name (first args) b (assoc (web/json-body req) :_id name)]
                       (if files? (do (store/put-tree! dir realm name b) (reload! srv)) (swap! tenant assoc-in [:trees name] b))
                       (web/json 200 (assoc (get-in @tenant [:trees name]) :_rev "0")))
      [:nodes "GET"] (if-let [n (get-in t [:nodes (nth args 2)])]
                       (web/json 200 n)
                       (web/error 404 "node not found"))
      [:nodes "PUT"] (let [[type version id] args
                           cfg (web/json-body req)]
                       (if files?
                         (do (store/put-node! dir realm type version id cfg) (reload! srv))
                         (swap! tenant assoc-in [:nodes id] (assoc cfg :_type {:_id type :version version} :_id id)))
                       (web/json 200 (get-in @tenant [:nodes id])))
      [:scripts "GET"] (if-let [id (first args)]
                         (if-let [s (get-in t [:scripts id])]
                           (web/json 200 (store/script-rest s))
                           (web/error 404 "script not found"))
                         (web/json 200 {:result (mapv store/script-rest (vals (:scripts t))) :resultCount (count (:scripts t))}))
      [:scripts "PUT"] (let [id (first args) b (web/json-body req)]
                         (if files?
                           (do (store/put-script! dir realm id b) (reload! srv))
                           (swap! tenant assoc-in [:scripts id] (decode-script (assoc b :_id id))))
                         (web/json 200 (store/script-rest (get-in @tenant [:scripts id]))))
      (web/error 405 (str m " " (name kind))))))

;; ---- routing -------------------------------------------------------------------------------

(def ^:private routes
  (let [pre "^/am/json(?:/realms/root/realms/([^/]+))?/"
        tre (str pre "realm-config/authentication/authenticationtrees/")]
    [[#"^/am/json/serverinfo/([^/]+)$" :am :serverinfo]
     [(re-pattern (str pre "authenticate$")) :journeys :authenticate]
     [(re-pattern (str pre "sessions/?$")) :am :sessions]
     [(re-pattern (str tre "trees(?:/([^/]+))?$")) :journeys :trees]
     [(re-pattern (str tre "nodes/([^/]+)/([^/]+)/([^/]+)$")) :journeys :nodes]
     [(re-pattern (str pre "scripts(?:/([^/]+))?$")) :journeys :scripts]
     [#"^/am/oauth2(?:/realms/root/realms/([^/]+))?/(.+)$" :oauth :oauth]
     [#"^/am/XUI/?$" :am :login-page]
     [#"^/openidm/managed/([^/]+)(?:/([^/]+))?$" :idm :idm]
     [#"^/environment/(variables|secrets)(?:/([^/]+))?$" :esv :env]]))

(defn handle
  "One request map in, one response map out. Exposed so tests can skip the socket."
  [{:keys [realm opts] :as srv} req]
  (let [hit (some (fn [[re module kind]] (when-let [m (re-matches re (:path req))] [module kind m])) routes)]
    (if-not hit
      (web/error 404 (str "no route " (:path req)))
      (let [[module kind m] hit
            r (or (second m) realm)]
        (cond
          (not ((:modules opts) module))
          (web/error 404 (str (:path req) " belongs to module " (name module) ", which is off in this run"))

          :else
          (case kind
            :serverinfo (if-let [i (am/serverinfo srv (second m))] (web/json 200 i) (web/error 404 "no such serverinfo"))
            :authenticate (authenticate srv req r)
            :sessions (am/sessions srv req r)
            (:trees :nodes :scripts) (if (allowed? srv req "fr:am:*")
                                       (manage srv req r kind (vec (drop 2 m)))
                                       (deny srv req))
            :oauth (oauth/handle srv req (or (second m) (web/param req "realm") "root") (nth m 2))
            :login-page (am/login-page req)
            :idm (if (allowed? srv req "fr:idm:*")
                   (idm/handle (:idm srv) req (nth m 1) (nth m 2))
                   (deny srv req))
            :env (if (allowed? srv req "fr:idc:esv:*")
                   (am/environment (:tenant srv) req (nth m 1) (nth m 2))
                   (deny srv req))))))))

;; ---- the socket ----------------------------------------------------------------------------

(defn- ->request [^HttpExchange ex]
  (let [uri (.getRequestURI ex)]
    {:method (.getRequestMethod ex)
     :path (.getPath uri)
     :query (web/decode-form (.getRawQuery uri))
     :headers (into {} (for [[k vs] (.getRequestHeaders ex)] [(str/lower-case k) (vec vs)]))
     :body (slurp (.getRequestBody ex))}))

(defn- send! [^HttpExchange ex {:keys [status headers body]}]
  (let [bytes (.getBytes ^String (if (string? body) body (json/generate-string body)) "UTF-8")
        hs (.getResponseHeaders ex)]
    (doseq [[k v] headers, x (if (sequential? v) v [v])] (.add hs k (str x)))
    (.sendResponseHeaders ex status (if (zero? (count bytes)) -1 (count bytes)))
    (with-open [o (.getResponseBody ex)] (.write o bytes))))

(defn- seed-identities
  "The IDM store at start: :idm from services.edn as given, plus every :users entry as a
  <realm>_user (attributes flattened, :managed merged in), so the old fakes and REST agree."
  [services realm]
  (let [store (atom {})
        users (for [[name {:keys [password attrs]}] (:users services)]
                (merge {:_id (str (UUID/nameUUIDFromBytes (.getBytes (str realm "/" name) "UTF-8")))
                        :userName name :password password :accountStatus "active"}
                       (update-vals (update-keys attrs keyword) #(if (and (sequential? %) (= 1 (count %))) (first %) %))
                       (get-in services [:managed name])))]
    (doseq [u users] (idm/create! store (str realm "_user") u))
    (doseq [[type objs] (:idm services), o objs] (idm/create! store type o))
    store))

(defn start!
  "Start the fake tenant. opts:
    :port 8080 (0 = any)  :dir \"tenant\"  :realm \"alpha\"  :frodo nil (a Frodo export to load instead)
    :services nil (path of a services.edn to use instead of <dir>/services.edn)
    :modules all-modules  :public-url \"http://127.0.0.1:<port>\"  :token-format :jwt | :opaque
    :cookie-name \"iPlanetDirectoryPro\"  :dev-token \"local-dev\"  :access-ttl 3600
  Returns the server map (atoms :tenant :sessions :sso :tokens :codes :idm); stop with (stop! it)."
  [{:keys [port dir realm frodo services] :or {port 8080 dir "tenant" realm "alpha"} :as o}]
  (let [http (HttpServer/create (InetSocketAddress. "127.0.0.1" (int port)) 0)
        port (.getPort (.getAddress http))
        opts (merge {:modules all-modules :public-url (str "http://127.0.0.1:" port) :token-format :jwt
                     :cookie-name "iPlanetDirectoryPro" :dev-token "local-dev"}
                    (dissoc o :port :dir :realm :services))
        t (if frodo (frodo/load-tenant frodo realm) (store/load-tenant dir realm))
        t (cond-> t services (update :services merge (edn/read-string (slurp services))))
        idm (seed-identities (:services t) realm)
        srv {:tenant (atom (update t :services assoc :idm idm :realm realm))
             :sessions (atom {}) :sso (atom {}) :tokens (atom {}) :codes (atom {}) :idm idm
             :key (jwt/new-key) :dir (when-not frodo dir) :realm realm :opts opts}]
    (.createContext http "/" (reify HttpHandler
                               (handle [_ ex]
                                 (send! ex (try (handle srv (->request ex))
                                                (catch Throwable e (web/error 500 (str e))))))))
    (.start http)
    (assoc srv :server http :port port)))

(defn stop! [{:keys [server]}] (.stop ^HttpServer server 0))

(defn -main [& [port dir]]
  (let [s (start! {:port (Integer/parseInt (or port "8080")) :dir (or dir "tenant")})]
    (println "sling fake tenant on" (get-in s [:opts :public-url]) "dir" (:dir s))
    @(promise)))
