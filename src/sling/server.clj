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
            [sling.mfa]
            [sling.oauth :as oauth]
            [sling.openidm :as openidm]
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

(defn- idm-context
  "The request context an IDM script sees as `context`, from whoever is calling."
  [srv req realm]
  (let [claims (some->> (web/bearer req) (oauth/token-claims srv))
        sso (oauth/sso-session srv req)]
    {:security {:authenticationId (or (:subname claims) (:username sso) "local-dev")
                :authorization {:id (or (:sub claims) (:user-id sso) "local-dev")
                                :component (if (and sso (not claims)) (str "managed/" realm "_user") "internal/user")
                                :roles (if (and sso (not claims)) ["internal/role/openidm-authorized"] ["internal/role/openidm-admin"])
                                :scopes (vec (:scope claims))}}
     :http {:method (:method req) :path (:path req) :headers (update-vals (:headers req) first)}}))

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
        suspended-id (web/param req "suspendedId")
        res (cond
              suspended-id
              (if-let [s (get @sessions (str "suspended:" suspended-id))]
                (do (swap! sessions dissoc (str "suspended:" suspended-id)) (engine/resume-suspended t s))
                {:status :failure :reason "unknown or used suspendedId" :session nil})
              (:authId in)
              (if-let [s (get @sessions (:authId in))]
                (engine/resume t s (:callbacks in))
                {:status :failure :reason "unknown or expired authId" :session nil})
              :else
              (engine/start t journey {:headers (:headers req) :parameters (:query req) :cookies (web/cookies req)}))
        dbg (when debug? {:_sling {:reason (:reason res) :trace (get-in res [:session :trace])
                                        :sessionProperties (get-in res [:session :props])}})]
    (when (and (:authId in) (not= :callbacks (:status res))) (swap! sessions dissoc (:authId in)))
    (case (:status res)
      :suspended (do (swap! sessions assoc (str "suspended:" (get-in res [:suspend :id])) (:session res))
                     (web/json 200 (merge {:authId (str (UUID/randomUUID)) :callbacks (:callbacks res)} dbg)))
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
      [:nodes "PUT"] (let [[type version id] (update args 1 #(or % "1.0"))
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
     [(re-pattern (str tre "nodes/([^/]+)(?:/([0-9.]+))?/([^/]+)$")) :journeys :nodes]
     [(re-pattern (str pre "realm-config/(federation/circlesoftrust|saml2|services/SocialIdentityProviders)$")) :journeys :empty]
     [(re-pattern (str pre "scripts(?:/([^/]+))?$")) :journeys :scripts]
     [#"^/am/oauth2(?:/realms/root/realms/([^/]+))?/(.+)$" :oauth :oauth]
     [#"^/am/XUI/?$" :am :login-page]
     [#"^/openidm/managed/([^/]+)(?:/([^/]+))?$" :idm :idm]
     [#"^/openidm/endpoint/([^/]+)(?:/(.+))?$" :idm :endpoint]
     [#"^/openidm/system/([^/]+)/([^/]+)(?:/([^/]+))?$" :idm :system]
     [#"^/openidm/recon$" :idm :recon]
     [#"^/openidm/config(?:/(.+))?$" :idm :config]
     [#"^/openidm/system$" :idm :system-actions]
     [#"^/sling/sync$" :am :sync-log]
     [#"^/sling/outbox$" :am :outbox]
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
            ;; what a journey export also reads; this tenant has none of them
            :empty (if (allowed? srv req "fr:am:*") (web/json 200 {:result [] :resultCount 0}) (deny srv req))
            :idm (if (allowed? srv req "fr:idm:*")
                   (openidm/handle-managed (:openidm srv) (idm-context srv req realm) req (nth m 1) (nth m 2))
                   (deny srv req))
            ;; end users call custom endpoints too, with their session; the script decides
            :endpoint (if (allowed? srv req "fr:idm:*")
                        (openidm/handle-endpoint (:openidm srv) (idm-context srv req realm) req (nth m 1) (nth m 2))
                        (deny srv req))
            :system (if (allowed? srv req "fr:idm:*")
                      (openidm/handle-managed (:openidm srv) (idm-context srv req realm) req
                                              (str "system/" (nth m 1) "/" (nth m 2)) (nth m 3))
                      (deny srv req))
            :recon (if (allowed? srv req "fr:idm:*")
                     (try (web/json 200 (openidm/recon (:openidm srv) (idm-context srv req realm) (web/param req "mapping")))
                          (catch clojure.lang.ExceptionInfo e (web/error (or (:code (ex-data e)) 400) (ex-message e))))
                     (deny srv req))
            :config (if (allowed? srv req "fr:idm:*") (openidm/handle-config (:openidm srv) req (second m)) (deny srv req))
            ;; Frodo asks after the connector servers; this tenant has none connected
            :system-actions (if (allowed? srv req "fr:idm:*") (web/json 200 {:openicf []}) (deny srv req))
            :sync-log (web/json 200 {:result @(:sync-log (:openidm srv)) :links @(:links (:openidm srv))})
            :outbox (if (= "DELETE" (:method req))
                      (do (reset! (get-in @(:tenant srv) [:services :outbox]) []) (web/json 200 {:result []}))
                      (web/json 200 {:result @(get-in @(:tenant srv) [:services :outbox])}))
            :env (if (allowed? srv req "fr:idc:esv:*")
                   (am/environment (:tenant srv) req (nth m 1) (nth m 2))
                   (deny srv req))))))))

;; ---- CORS ----------------------------------------------------------------------------------

(defn- origin-allowed?
  "An SPA's origin may call with credentials: those in :cors-origins, or by default any page
  served from localhost / 127.0.0.1, which is where a developer's SPA runs."
  [{:keys [opts]} origin]
  (when origin
    (if-let [allowed (:cors-origins opts)]
      (contains? (set allowed) origin)
      (boolean (re-matches #"https?://(localhost|127\.0\.0\.1)(:\d+)?" origin)))))

(defn with-cors
  "Answer preflights and add the CORS headers a browser needs for fetch(..., {credentials: 'include'})."
  [srv req respond]
  (let [origin (web/header req "origin")
        ok? (origin-allowed? srv origin)
        headers (when ok? {"Access-Control-Allow-Origin" origin "Access-Control-Allow-Credentials" "true"
                           "Vary" "Origin" "Access-Control-Expose-Headers" "Location, Content-Type"})]
    (if (and (= "OPTIONS" (:method req)) (web/header req "access-control-request-method"))
      {:status (if ok? 204 403) :body ""
       :headers (merge headers (when ok? {"Access-Control-Allow-Methods" "GET, POST, PUT, PATCH, DELETE, OPTIONS"
                                          "Access-Control-Allow-Headers" (or (web/header req "access-control-request-headers") "*")
                                          "Access-Control-Max-Age" "600"}))}
      (update (respond) :headers merge headers))))

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
    :port 8080 (0 = any)  :bind \"127.0.0.1\" (0.0.0.0 for containers; set :public-url to what they see)
    :dir \"tenant\"  :realm \"alpha\"  :frodo nil (a Frodo export to load instead)
    :services nil (path of a services.edn to use instead of <dir>/services.edn)
    :modules all-modules  :public-url \"http://127.0.0.1:<port>\"  :token-format :jwt | :opaque
    :cookie-name \"iPlanetDirectoryPro\"  :dev-token \"local-dev\"  :access-ttl 3600
    :cors-origins nil (SPA origins allowed to call with credentials; default any localhost page)
  Returns the server map (atoms :tenant :sessions :sso :tokens :codes :idm); stop with (stop! it)."
  [{:keys [port bind dir realm frodo services] :or {port 8080 bind "127.0.0.1" dir "tenant" realm "alpha"} :as o}]
  (let [http (HttpServer/create (InetSocketAddress. ^String bind (int port)) 0)
        port (.getPort (.getAddress http))
        opts (merge {:modules all-modules :public-url (str "http://127.0.0.1:" port) :token-format :jwt
                     :cookie-name "iPlanetDirectoryPro" :dev-token "local-dev"}
                    (dissoc o :port :bind :dir :realm :services))
        t (if frodo (frodo/load-tenant frodo realm) (store/load-tenant dir realm))
        t (cond-> t services (update :services merge (edn/read-string (slurp services))))
        idm (seed-identities (:services t) realm)
        tenant (atom t)
        env {:tenant tenant :idm idm :links (atom {}) :sync-log (atom []) :connectors (atom {})}
        internal {:security {:authenticationId "sling" :authorization {:id "sling" :component "internal/user"
                                                                             :roles ["internal/role/openidm-admin"]}}}
        _ (swap! tenant update :services assoc :idm idm :realm realm :outbox (atom []) :public-url (:public-url opts)
                 :openidm (fn [op args] (openidm/dispatch env internal 0 op args)))
        srv {:tenant tenant :openidm env
             :sessions (atom {}) :sso (atom {}) :tokens (atom {}) :codes (atom {}) :idm idm
             :key (jwt/new-key) :dir (when-not frodo dir) :realm realm :opts opts}]
    (.createContext http "/" (reify HttpHandler
                               (handle [_ ex]
                                 (send! ex (let [req (->request ex)]
                                             (try (with-cors srv req #(handle srv req))
                                                  (catch Throwable e (web/error 500 (str e)))))))))
    (.start http)
    (assoc srv :server http :port port)))

(defn stop! [{:keys [server]}] (.stop ^HttpServer server 0))

(defn- cli-opts
  "--port 8080 --bind 127.0.0.1 --dir tenant --frodo <export> --services <edn> --modules oauth,idm --realm alpha
  --token-format jwt|opaque --public-url <url> --cookie-name <name> --cors-origins <o1,o2>; bare args are port then dir."
  [args]
  (loop [[a b & more :as as] args o {} bare []]
    (cond
      (empty? as) (cond-> o (first bare) (assoc :port (first bare)) (second bare) (assoc :dir (second bare)))
      (str/starts-with? a "--") (recur more (assoc o (keyword (subs a 2)) b) bare)
      :else (recur (rest as) o (conj bare a)))))

(defn -main [& args]
  (let [{:keys [port modules token-format cors-origins] :as o} (cli-opts args)
        s (start! (cond-> (assoc o :port (Integer/parseInt (or port "8080")))
                    cors-origins (assoc :cors-origins (str/split cors-origins #","))
                    modules (assoc :modules (set (map keyword (str/split modules #","))))
                    token-format (assoc :token-format (keyword token-format))))]
    (println "sling fake tenant on" (get-in s [:opts :public-url])
             (if (:frodo o) (str "frodo export " (:frodo o)) (str "dir " (:dir s)))
             "modules" (str/join "," (sort (map name (get-in s [:opts :modules])))))
    @(promise)))
