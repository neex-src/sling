(ns sling.openidm
  "The IDM router: every managed-object operation goes through here, from REST and from scripts
  alike, so the managed object scripts (onCreate, postCreate, onUpdate, postUpdate, onDelete,
  postDelete, onRead, onValidate) run whoever writes, as on the platform. Also the custom
  endpoints (endpoint/<name>, scripts from the export's global/idm/endpoint) and the actions
  scripts use most: external/rest call, external/email send|sendTemplate.

  `env` is {:tenant atom :idm store-atom}; schemas come from tenant :managed-schemas, endpoints from
  :idm-endpoints, ESVs and the outside world from :services. `ctx` is the IDM request context the
  scripts see as `context` ({:security {:authenticationId .. :authorization {..}} :http {..}})."
  (:require [cheshire.core :as json]
            [clojure.string :as str]
            [sling.idm :as idm]
            [sling.idmscript :as idmscript]
            [sling.outside :as outside]
            [sling.web :as web])
  (:import (java.security MessageDigest)
           (java.util UUID)))

(def ^:private max-depth 12)

(defn- fail [code msg] (throw (ex-info msg {:code code})))

(defn- split-resource
  "\"managed/alpha_user/123\" -> [\"managed\" \"alpha_user\" \"123\"]"
  [res]
  (let [[kind a & more] (str/split (str/replace (str res) #"^/+" "") #"/")]
    [kind a (when (seq more) (str/join "/" more))]))

(defn- script-of
  "Source of a configured script ({:type :source} or {:type :file}), or a refusal for Groovy."
  [{:keys [type source file]} what]
  (cond
    (and type (not= type "text/javascript")) (fail 501 (str what " is " type ", which sling does not run"))
    source source
    :else (fail 501 (str what " points at file " (pr-str file) ", which an export does not carry"))))

(declare dispatch)

(defn- run-script [env ctx depth cfg what vars]
  (let [r (idmscript/run (script-of cfg what) (assoc vars :context ctx)
                         (fn [op args] (dispatch env ctx (inc depth) op args)))]
    (when-let [e (:error r)] (fail (:code e) (str what ": " (:message e))))
    r))

(defn- trigger
  "Run the managed object's `hook` script if it has one; returns the script result or nil."
  [env ctx depth type hook vars]
  (when-let [cfg (get-in @(:tenant env) [:managed-schemas type (keyword hook)])]
    (run-script env ctx depth cfg (str "managed/" type " " hook) (assoc vars :resourceName (str "managed/" type)))))

;; ---- managed objects -----------------------------------------------------------------------

(defn create [env ctx depth type id content]
  (let [store (:idm env)
        id (or id (:_id content) (str (UUID/randomUUID)))
        _ (when (idm/read-obj store type id) (fail 412 (str "managed/" type "/" id " already exists")))
        obj (assoc content :_id id)
        obj (or (:object (trigger env ctx depth type "onCreate" {:object obj :newObject obj})) obj)
        _ (trigger env ctx depth type "onValidate" {:object obj :value obj})
        saved (idm/create! store type (assoc obj :_id id))]
    (trigger env ctx depth type "postCreate" {:object saved :newObject saved})
    saved))

(defn read-obj [env ctx depth type id]
  (when-let [o (idm/read-obj (:idm env) type id)]
    (or (:object (trigger env ctx depth type "onRead" {:object o})) o)))

(defn- write [env ctx depth type id old new]
  (let [obj (or (:object (trigger env ctx depth type "onUpdate" {:object new :oldObject old :newObject new})) new)
        _ (trigger env ctx depth type "onValidate" {:object obj :value obj})
        saved (idm/replace! (:idm env) type id obj)]
    (trigger env ctx depth type "postUpdate" {:object saved :oldObject old :newObject saved})
    saved))

(defn update-obj [env ctx depth type id rev content]
  (if-let [old (idm/read-obj (:idm env) type id)]
    (do (when (and rev (not= rev "*") (not= rev (:_rev old))) (fail 412 "revision does not match"))
        (write env ctx depth type id old (assoc content :_id id)))
    (create env ctx depth type id content)))

(defn patch-obj [env ctx depth type id rev ops]
  (let [old (or (idm/read-obj (:idm env) type id) (fail 404 (str "managed/" type "/" id " not found")))]
    (when (and rev (not= rev "*") (not= rev (:_rev old))) (fail 412 "revision does not match"))
    (write env ctx depth type id old (idm/apply-ops old ops))))

(defn delete-obj [env ctx depth type id]
  (let [old (or (idm/read-obj (:idm env) type id) (fail 404 (str "managed/" type "/" id " not found")))]
    (trigger env ctx depth type "onDelete" {:object old})
    (idm/delete! (:idm env) type id)
    (trigger env ctx depth type "postDelete" {:oldObject old})
    old))

;; ---- custom endpoints ----------------------------------------------------------------------

(defn endpoint
  "Run endpoint/<name>. req: {:method create|read|update|patch|delete|query|action, :content ..,
  :additionalParameters {..}, :resourcePath s, :action s, :queryFilter s ...}."
  [env ctx depth name req]
  (let [cfg (or (get-in @(:tenant env) [:idm-endpoints name]) (fail 404 (str "endpoint/" name " not found")))]
    (:value (run-script env ctx depth cfg (str "endpoint/" name) {:request req}))))

;; ---- actions -------------------------------------------------------------------------------

(defn- external-rest [services {:keys [url method headers body contentType forceWrap]}]
  (let [r (outside/http services {:uri url :method method
                                  :headers (cond-> (or headers {}) contentType (assoc "Content-Type" contentType))
                                  :body (cond (nil? body) nil (string? body) body :else (json/generate-string body))})
        parsed (try (json/parse-string (:body r) true) (catch Exception _ (:body r)))]
    (cond
      forceWrap {:code (:status r) :headers (:headers r) :body (:body r)}
      (<= 200 (:status r) 299) parsed
      :else (fail (:status r) (str "external/rest " url " answered " (:status r) ": " (:body r))))))

(defn- email [env action content]
  (let [{:keys [to from subject body templateName object]} content
        t @(:tenant env)
        tpl (when (= action "sendTemplate") (get-in t [:email-templates templateName]))]
    (outside/send-mail! (:services t) {:kind "email" :to to :from from
                                       :subject (or subject (some-> tpl :subject :en))
                                       :body (or body (some-> tpl :message :en)) :template templateName :object object})
    {:status "OK" :message "Email sent"}))

(defn- action [env ctx depth {:keys [resource action content params]}]
  (let [[kind a rest] (split-resource resource)
        services (:services @(:tenant env))]
    (case kind
      "external" (case [a action]
                   ["rest" "call"] (external-rest services content)
                   (["email" "send"] ["email" "sendTemplate"]) (email env action content)
                   (fail 501 (str "action " action " on external/" a " is not modelled")))
      "endpoint" (endpoint env ctx depth a {:method "action" :action action :content content
                                            :additionalParameters (or params {}) :resourcePath (or rest "")})
      (fail 501 (str "action " action " on " resource " is not modelled")))))

;; ---- the dispatcher scripts call ------------------------------------------------------------

(defn- sha [alg v] (str/join (map #(format "%02x" %) (.digest (MessageDigest/getInstance alg) (.getBytes (str v) "UTF-8")))))

(defn dispatch
  "One openidm.* call from a script (or from REST, with depth 0)."
  [env ctx depth op {:keys [resource id content params fields rev ops] :as args}]
  (when (> depth max-depth) (fail 508 (str "scripts called openidm " max-depth " levels deep: a trigger loop?")))
  (let [[kind type oid] (split-resource resource)
        managed! #(when-not (= kind "managed") (fail 501 (str op " on " resource " is not modelled (only managed/ and endpoint/)")))
        view #(idm/public-view % fields)]
    (case op
      "create" (if (= kind "endpoint")
                 (endpoint env ctx depth type {:method "create" :content content :newResourceId id
                                               :additionalParameters (or params {}) :resourcePath (or oid "")})
                 (do (managed!) (view (create env ctx depth type id content))))
      "read" (if (= kind "endpoint")
               (endpoint env ctx depth type {:method "read" :additionalParameters (or params {}) :resourcePath (or oid "")})
               (do (managed!) (some-> (read-obj env ctx depth type oid) view)))
      "update" (if (= kind "endpoint")
                 (endpoint env ctx depth type {:method "update" :content content :revision rev
                                               :additionalParameters (or params {}) :resourcePath (or oid "")})
                 (do (managed!) (view (update-obj env ctx depth type oid rev content))))
      "patch" (if (= kind "endpoint")
                (endpoint env ctx depth type {:method "patch" :patchOperations ops :revision rev
                                              :additionalParameters (or params {}) :resourcePath (or oid "")})
                (do (managed!) (view (patch-obj env ctx depth type oid rev ops))))
      "delete" (if (= kind "endpoint")
                 (endpoint env ctx depth type {:method "delete" :revision rev :additionalParameters (or params {}) :resourcePath (or oid "")})
                 (do (managed!) (view (delete-obj env ctx depth type oid))))
      "query" (if (= kind "endpoint")
                (endpoint env ctx depth type (merge {:method "query" :additionalParameters (dissoc params :_queryFilter :_queryId)
                                                     :resourcePath (or oid "")}
                                                    (when-let [q (:_queryFilter params)] {:queryFilter q})
                                                    (when-let [q (:_queryId params)] {:queryId q})))
                (do (managed!)
                    (idm/query (:idm env) type (cond-> (update-vals (update-keys (or params {}) name) str)
                                                 (seq fields) (assoc "_fields" (str/join "," fields))))))
      "action" (action env ctx depth args)
      "property" (let [k (:key args) s (:services @(:tenant env))] (or (get-in s [:esv k]) (get-in s [:secrets k])))
      "hash" {:$crypto {:type "salted-hash" :value {:algorithm (or (:algorithm args) "SHA-256") :data (sha "SHA-256" (:value args))}}}
      "matches" (= (sha "SHA-256" (:value args)) (get-in args [:hashed :$crypto :value :data]))
      "uuid" (str (UUID/randomUUID))
      (fail 501 (str "openidm." op " is not modelled")))))

;; ---- REST ----------------------------------------------------------------------------------

(defn- rest-method
  "The IDM request method a REST call stands for."
  [req]
  (let [m (:method req) a (web/param req "_action")]
    (cond
      (and (= m "GET") (or (web/param req "_queryFilter") (web/param req "_queryId"))) "query"
      (= m "GET") "read"
      (and (= m "POST") (contains? #{nil "create"} a)) "create"
      (= m "POST") "action"
      (= m "PUT") "update"
      (= m "PATCH") "patch"
      (= m "DELETE") "delete")))

(defn handle-endpoint
  "/openidm/endpoint/<name>[/<path>] over REST."
  [env ctx req name path]
  (try
    (let [q (dissoc (update-vals (:query req) first) "_action" "_queryFilter" "_queryId" "_fields")
          body (web/json-body req)
          method (rest-method req)
          v (endpoint env ctx 0 name (cond-> {:method method :resourcePath (or path "") :additionalParameters q
                                              :content body}
                                       (= method "action") (assoc :action (web/param req "_action"))
                                       (= method "query") (assoc :queryFilter (web/param req "_queryFilter")
                                                                 :queryId (web/param req "_queryId"))
                                       (= method "patch") (assoc :patchOperations body)
                                       (#{"update" "patch" "delete"} method) (assoc :revision (web/header req "if-match"))))]
      (web/json 200 (if (and (= method "query") (sequential? v)) {:result v :resultCount (count v)} v)))
    (catch clojure.lang.ExceptionInfo e (web/error (or (:code (ex-data e)) 500) (ex-message e)))))

(defn handle-managed
  "/openidm/managed/<type>[/<id>] over REST, triggers included."
  [env ctx req type id]
  (let [method (rest-method req)
        fields (some-> (web/param req "_fields") (str/split #","))
        body (delay (web/json-body req))
        out (fn [status o] (web/json status (idm/public-view o fields)))]
    (try
      (case [method (some? id)]
        ["query" false] (web/json 200 (idm/query (:idm env) type (update-vals (:query req) first)))
        ["read" false] (web/error 400 "query requests need _queryFilter (use _queryFilter=true for all)")
        ["create" false] (out 201 (create env ctx 0 type nil @body))
        ["read" true] (if-let [o (read-obj env ctx 0 type id)] (out 200 o) (web/error 404 (str "managed/" type "/" id " not found")))
        ["update" true] (let [old (idm/read-obj (:idm env) type id)]
                          (if (and old (= "*" (web/header req "if-none-match")))
                            (web/error 412 "object already exists")
                            (out (if old 200 201) (update-obj env ctx 0 type id (web/header req "if-match") @body))))
        ["patch" true] (out 200 (patch-obj env ctx 0 type id (web/header req "if-match") @body))
        ["action" true] (if (= "patch" (web/param req "_action"))
                          (out 200 (patch-obj env ctx 0 type id (web/header req "if-match") @body))
                          (web/error 501 (str "action " (web/param req "_action") " is not modelled")))
        ["delete" true] (out 200 (delete-obj env ctx 0 type id))
        (web/error 405 (str (:method req) (when id (str " on one object")))))
      (catch clojure.lang.ExceptionInfo e (web/error (or (:code (ex-data e)) 400) (ex-message e))))))
