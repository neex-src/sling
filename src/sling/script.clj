(ns sling.script
  "Runs one next-generation Scripted Decision script in GraalJS.

  The bindings (nodeState, action, callbacksBuilder, callbacks, requestHeaders, idRepository,
  httpClient, openidm, systemEnv, logger ...) are written in JS (resources/sling/bindings.js)
  from the public Ping docs. The only way out of the sandbox is `host`, which answers from the
  fakes in the `services` map:

    :users   {name {:password p :attrs {attr [values]}}}   idRepository, DataStoreDecision
    :esv     {key value}                                    systemEnv.getProperty
    :managed {name {...}}                                   openidm.read/query on managed/user
    :http    [{:match uri-or-prefix* :method m :response {:status n :body string-or-data}}]   first hit wins

  An unmatched httpClient call answers 599 and says so: a missing fake must be loud."
  (:require [cheshire.core :as json]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [sling.idm :as idm]
            [sling.outside :as outside])
  (:import (org.graalvm.polyglot Context Engine Source Value)
           (org.graalvm.polyglot.proxy ProxyExecutable)))

(def ^:private engine
  (delay (-> (Engine/newBuilder (into-array String ["js"]))
             (.option "engine.WarnInterpreterOnly" "false")
             (.build))))

(def ^:private prelude (delay (slurp (io/resource "sling/bindings.js"))))
(def ^:private legacy-prelude (delay (slurp (io/resource "sling/legacy.js"))))

(defn- http-send [services {:keys [uri options]}]
  (outside/http services {:uri uri :method (:method options) :headers (:headers options)
                          :body (let [b (:body options)] (when (some? b) (if (string? b) b (json/generate-string b))))}))

(defn- eq-filter [filter-str]
  (when-let [[_ field v] (re-matches #"/?(\w+) eq '([^']*)'" (str filter-str))]
    [(keyword field) v]))

(defn- openidm-query [{:keys [managed]} {:keys [params]}]
  (let [users (map (fn [[n m]] (assoc m :_id n :userName (or (:userName m) n))) managed)
        [f v] (eq-filter (:_queryFilter params))
        found (if f (filter #(= v (str (get % f))) users) users)]
    {:result (vec found) :resultCount (count found)}))

(declare idm-op*)

(defn- router-op
  "openidm.* through the server's IDM router (managed object scripts, endpoints, external/*).
  managed/user means the realm's users, as in journey scripts."
  [{:keys [openidm realm]} op {:keys [path] :as args}]
  (when-let [[_ verb] (re-matches #"openidm\.(\w+)" op)]
    (let [res (str/replace (str path) #"^managed/user(?=/|$)" (str "managed/" realm "_user"))
          a (-> args (dissoc :path) (assoc :resource res))]
      (try (openidm verb a)
           (catch clojure.lang.ExceptionInfo e
             (if (= 404 (:code (ex-data e))) nil (throw e)))))))

(defn- idm-op
  "The same calls answered from the IDM store the server shares with REST, when there is one."
  [{:keys [idm realm] :as services} op args]
  (if (and (:openidm services) (str/starts-with? op "openidm."))
    (router-op services op args)
    (idm-op* services op args)))

(defn- idm-op* [{:keys [idm realm]} op args]
  (let [users (str realm "_user")
        attr (fn [u a] (let [x (get u (keyword a))] (cond (nil? x) [] (sequential? x) (vec x) :else [x])))]
    (case op
      "idRepo.getAttribute" (some-> (idm/find-by idm users :userName (:user args)) (attr (:attr args)))
      "idRepo.exists" (some? (idm/find-by idm users :userName (:user args)))
      "openidm.read" (let [[_ type id] (re-matches #"managed/([^/]+)/(.+)" (:path args))
                           type (if (= type "user") users type)]
                       (some-> (idm/find-by idm type :userName id) (idm/public-view nil)))
      "openidm.query" (let [[_ type] (re-matches #"managed/([^/]+)" (:path args))]
                        (idm/query idm (if (= type "user") users type) (update-keys (:params args) name)))
      ::none)))

(declare legacy-op)

(defn host-op
  "The fake world one script call sees. Returns a Clojure value, or nil for 'not there'."
  [services op args]
  (let [r (if (:idm services) (idm-op services op args) ::none)]
    (if (not= r ::none) r (legacy-op services op args))))

(defn- legacy-op [services op args]
  (case op
    "idRepo.getAttribute" (when-let [u (get-in services [:users (:user args)])]
                            (vec (get-in u [:attrs (:attr args)])))
    "idRepo.exists" (contains? (:users services) (:user args))
    "env.get" (or (get-in services [:esv (:key args)]) (get-in services [:secrets (:key args)]))
    "http.send" (http-send services args)
    "openidm.read" (let [[_ n] (re-matches #"managed/user/(.+)" (:path args))]
                     (when-let [m (get-in services [:managed n])] (assoc m :_id n)))
    "openidm.query" (openidm-query services args)
    nil))

(defn run-script
  "Run `source` against `input` and the fakes in `services`.
  input: {:shared {} :transient {} :request {:headers {name [v]} :parameters {} :cookies {}}
          :callbacks [{:type \"NameCallback\" :value \"x\"}] :existing-session {}}
  Returns {:outcome s|nil :action {...} :callbacks [{:type :args}] :shared {} :transient {} :logs [] :error s|nil}.
  :shared/:transient hold only what the script wrote. With {:legacy true} the script runs with the
  legacy (1.0) bindings of legacy.js layered on top."
  ([source input services] (run-script source input services {}))
  ([source input services {:keys [legacy]}]
   (let [host (reify ProxyExecutable
                (execute [_ args]
                  (let [op (.asString ^Value (aget args 0))
                        a (json/parse-string (.asString ^Value (aget args 1)) true)
                        r (host-op services op a)]
                    (when (some? r) (json/generate-string r)))))
         in (json/generate-string
             {:shared (or (:shared input) {}) :transient (or (:transient input) {})
              :callbacks (or (:callbacks input) [])
              :existingSession (or (:existing-session input) {})
              :request (merge {:headers {} :parameters {} :cookies {}} (:request input))})]
     (with-open [ctx (-> (Context/newBuilder (into-array String ["js"])) (.engine @engine) (.build))]
       (try
         (let [factory (.eval ctx (Source/create "js" ^String @prelude))
               env (.execute factory (object-array [host in]))
               globals (.getBindings ctx "js")
               bindings (.getMember env "bindings")]
           (doseq [k (.getMemberKeys bindings)]
             (.putMember globals k (.getMember bindings k)))
           (let [env (if legacy
                       (let [l (.execute (.eval ctx (Source/create "js" ^String @legacy-prelude)) (object-array [env]))
                             lb (.getMember l "bindings")]
                         (doseq [k (.getMemberKeys lb)] (.putMember globals k (.getMember lb k)))
                         l)
                       env)]
           (.eval ctx (Source/create "js" ^String source))
           (let [r (json/parse-string (.asString (.invokeMember env "result" (object-array 0))) true)
                 a (:action r)]
             (-> r
                 (update :shared update-keys name)
                 (update :transient update-keys name)
                 (cond-> a (update-in [:action :sessionProps] update-keys name))
                 (assoc :outcome (:outcome a) :error nil)))))
         (catch Exception e
           {:outcome nil :callbacks [] :shared {} :transient {} :logs []
            :error (str "script error: " (ex-message e))}))))))
