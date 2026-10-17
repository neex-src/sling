(ns sling.server
  "The mock tenant: the same URLs the real one has, backed by the tenant/ directory.

    POST .../authenticate[?authIndexType=service&authIndexValue=<journey>]   the callback loop
    GET|PUT .../realm-config/authentication/authenticationtrees/trees[/<name>]
    GET|PUT .../realm-config/authentication/authenticationtrees/nodes/<type>/<version>/<id>
    GET|PUT .../scripts[/<uuid>]                                             source is base64

  A PUT writes the files, so `git diff` shows exactly what a deploy changed. Management calls
  need an Authorization or iPlanetDirectoryPro header (any value: this is not a security tool).
  Send `X-Sling-Debug: true` on /authenticate to get the reason and the node trace back.

  Usage: clojure -M -m sling.server [port] [tenant-dir]   (bb serve)"
  (:require [cheshire.core :as json]
            [clojure.string :as str]
            [sling.engine :as engine]
            [sling.store :as store])
  (:import (com.sun.net.httpserver HttpExchange HttpHandler HttpServer)
           (java.net InetSocketAddress URLDecoder)
           (java.util UUID)))

(defn- query-params [^HttpExchange ex]
  (let [q (.getRawQuery (.getRequestURI ex))]
    (reduce (fn [m kv]
              (let [[k v] (str/split kv #"=" 2)]
                (update m (URLDecoder/decode ^String k "UTF-8") (fnil conj [])
                        (URLDecoder/decode ^String (or v "") "UTF-8"))))
            {} (remove str/blank? (str/split (or q "") #"&")))))

(defn- request-headers [^HttpExchange ex]
  (into {} (for [[k vs] (.getRequestHeaders ex)] [(str/lower-case k) (vec vs)])))

(defn- body [^HttpExchange ex]
  (let [s (slurp (.getRequestBody ex))] (when-not (str/blank? s) (json/parse-string s true))))

(defn- respond [^HttpExchange ex status data]
  (let [bytes (.getBytes (json/generate-string data) "UTF-8")]
    (.add (.getResponseHeaders ex) "Content-Type" "application/json")
    (.sendResponseHeaders ex status (count bytes))
    (with-open [o (.getResponseBody ex)] (.write o bytes))))

(defn- authenticate [{:keys [tenant sessions]} ex realm]
  (let [t @tenant
        params (query-params ex)
        headers (request-headers ex)
        debug? (= "true" (some-> (get headers "x-sling-debug") first))
        in (body ex)
        journey (if (= ["service"] (get params "authIndexType"))
                  (first (get params "authIndexValue"))
                  (or (get-in t [:services :default-journey]) "Login"))
        res (if (:authId in)
              (if-let [s (get @sessions (:authId in))]
                (engine/resume t s (:callbacks in))
                {:status :failure :reason "unknown or expired authId" :session nil})
              (engine/start t journey {:headers headers :parameters params :cookies {}}))
        dbg (when debug? {:_sling {:reason (:reason res) :trace (get-in res [:session :trace])
                                        :sessionProperties (get-in res [:session :props])}})]
    (case (:status res)
      :callbacks (let [id (str (UUID/randomUUID))]
                   (swap! sessions assoc id (:session res))
                   (respond ex 200 (merge {:authId id :callbacks (:callbacks res)} dbg)))
      :success (do (when (:authId in) (swap! sessions dissoc (:authId in)))
                   (respond ex 200 (merge {:tokenId (str "AQIC" (UUID/randomUUID)) :successUrl (str "/enduser/?realm=/" realm)
                                           :realm (str "/" realm)} dbg)))
      (do (when (:authId in) (swap! sessions dissoc (:authId in)))
          (respond ex 401 (merge {:code 401 :reason "Unauthorized" :message "Login failure"} dbg))))))

(defn- reload! [{:keys [tenant dir realm]}]
  (swap! tenant (fn [old] (assoc (store/load-tenant dir realm) :services (:services old)))))

(defn- manage [{:keys [tenant dir] :as srv} ex realm kind args]
  (let [headers (request-headers ex)
        method (.getRequestMethod ex)]
    (if-not (or (get headers "authorization") (get headers "iplanetdirectorypro"))
      (respond ex 401 {:code 401 :reason "Unauthorized" :message "Access Denied"})
      (let [t @tenant]
        (case [kind method]
          [:trees "GET"] (if-let [name (first args)]
                           (if-let [tree (get-in t [:trees name])]
                             (respond ex 200 (assoc tree :_rev "0"))
                             (respond ex 404 {:code 404 :reason "Not Found" :message (str "Tree " name " not found")}))
                           (respond ex 200 {:result (vec (vals (:trees t))) :resultCount (count (:trees t))}))
          [:trees "PUT"] (let [name (first args) b (body ex)]
                           (store/put-tree! dir realm name b)
                           (reload! srv)
                           (respond ex 200 (assoc (get-in @tenant [:trees name]) :_rev "0")))
          [:nodes "GET"] (if-let [n (get-in t [:nodes (nth args 2)])]
                           (respond ex 200 n)
                           (respond ex 404 {:code 404 :reason "Not Found" :message "node not found"}))
          [:nodes "PUT"] (let [[type version id] args]
                           (store/put-node! dir realm type version id (body ex))
                           (reload! srv)
                           (respond ex 200 (get-in @tenant [:nodes id])))
          [:scripts "GET"] (if-let [id (first args)]
                             (if-let [s (get-in t [:scripts id])]
                               (respond ex 200 (store/script-rest s))
                               (respond ex 404 {:code 404 :reason "Not Found" :message "script not found"}))
                             (respond ex 200 {:result (mapv store/script-rest (vals (:scripts t)))
                                              :resultCount (count (:scripts t))}))
          [:scripts "PUT"] (let [id (first args)]
                             (store/put-script! dir realm id (body ex))
                             (reload! srv)
                             (respond ex 200 (store/script-rest (get-in @tenant [:scripts id]))))
          (respond ex 405 {:code 405 :reason "Method Not Allowed" :message (str method " " kind)}))))))

(def ^:private routes
  (let [pre "^/am/json(?:/realms/root/realms/([^/]+))?/"
        tre (str pre "realm-config/authentication/authenticationtrees/")]
    [[(re-pattern (str pre "authenticate$")) :authenticate]
     [(re-pattern (str tre "trees(?:/([^/]+))?$")) :trees]
     [(re-pattern (str tre "nodes/([^/]+)/([^/]+)/([^/]+)$")) :nodes]
     [(re-pattern (str pre "scripts(?:/([^/]+))?$")) :scripts]]))

(defn- handler [{:keys [realm] :as srv}]
  (reify HttpHandler
    (handle [_ ex]
      (try
        (let [path (.getPath (.getRequestURI ex))
              hit (some (fn [[re kind]] (when-let [m (re-matches re path)] [kind m])) routes)]
          (if-not hit
            (respond ex 404 {:code 404 :reason "Not Found" :message (str "no route " path)})
            (let [[kind m] hit
                  r (or (second m) realm)]
              (if (= kind :authenticate)
                (authenticate srv ex r)
                (manage srv ex r kind (vec (drop 2 m)))))))
        (catch Throwable e
          (respond ex 500 {:code 500 :reason "Internal Server Error" :message (str e)}))))))

(defn start!
  "Start the mock. opts: {:port (0 = any) :dir \"tenant\" :realm \"alpha\"}.
  Returns {:server :port :tenant atom :sessions atom}; stop with (stop! it)."
  [{:keys [port dir realm] :or {port 8080 dir "tenant" realm "alpha"}}]
  (let [srv {:tenant (atom (store/load-tenant dir realm)) :sessions (atom {}) :dir dir :realm realm}
        http (HttpServer/create (InetSocketAddress. "127.0.0.1" (int port)) 0)]
    (.createContext http "/" (handler srv))
    (.start http)
    (assoc srv :server http :port (.getPort (.getAddress http)))))

(defn stop! [{:keys [server]}] (.stop ^HttpServer server 0))

(defn -main [& [port dir]]
  (let [s (start! {:port (Integer/parseInt (or port "8080")) :dir (or dir "tenant")})]
    (println "sling mock tenant on http://127.0.0.1:" (:port s) "dir" (:dir s))
    @(promise)))
