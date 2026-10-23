(ns sling.openidm
  "The IDM router: every managed-object operation goes through here, from REST and from scripts
  alike, so the managed object scripts (onCreate, postCreate, onUpdate, postUpdate, onDelete,
  postDelete, onRead, onValidate) run whoever writes, as on the platform. Also the custom
  endpoints (endpoint/<name>, scripts from the export's global/idm/endpoint) and the actions
  scripts use most: external/rest call, external/email send|sendTemplate.

  Sync: every write to a mapping's source (managed/... or system/...) runs that mapping at once
  (implicit sync): validSource, situation, the policy's action (or its script), properties with
  their conditions and transforms, the mapping's onCreate script, links kept per mapping. Recon runs
  a whole mapping. System objects live in memory; GET /sling/sync shows what sync did.

  `env` is {:tenant atom :idm store-atom :links atom :sync-log atom}; schemas come from tenant :managed-schemas, endpoints from
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

;; ---- managed and system objects ----------------------------------------------------------
;; `type` is the store key: "alpha_user" for managed/alpha_user, "system/HR/__ACCOUNT__" for a
;; system object class (kept in memory here; a connector backend would take its place).

(declare sync-change!)

(defn create [env ctx depth type id content]
  (let [store (:idm env)
        id (or id (:_id content) (str (UUID/randomUUID)))
        _ (when (idm/read-obj store type id) (fail 412 (str "managed/" type "/" id " already exists")))
        obj (assoc content :_id id)
        obj (or (:object (trigger env ctx depth type "onCreate" {:object obj :newObject obj})) obj)
        _ (trigger env ctx depth type "onValidate" {:object obj :value obj})
        saved (idm/create! store type (assoc obj :_id id))]
    (trigger env ctx depth type "postCreate" {:object saved :newObject saved})
    (sync-change! env ctx depth type id saved)
    saved))

(defn read-obj [env ctx depth type id]
  (when-let [o (idm/read-obj (:idm env) type id)]
    (or (:object (trigger env ctx depth type "onRead" {:object o})) o)))

(defn- write [env ctx depth type id old new]
  (let [obj (or (:object (trigger env ctx depth type "onUpdate" {:object new :oldObject old :newObject new})) new)
        _ (trigger env ctx depth type "onValidate" {:object obj :value obj})
        saved (idm/replace! (:idm env) type id obj)]
    (trigger env ctx depth type "postUpdate" {:object saved :oldObject old :newObject saved})
    (sync-change! env ctx depth type id saved)
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
    (sync-change! env ctx depth type id nil)
    old))

;; ---- sync: mappings between managed and system objects ------------------------------------

(defn- source-res [type] (if (str/starts-with? type "system/") type (str "managed/" type)))
(defn- store-type [res] (str/replace res #"^managed/" ""))

(defn- esv-bool
  "enableSync and friends may be {\"$bool\": \"&{esv.x}\"}."
  [env x]
  (let [x (if (map? x) (or (:$bool x) (:value x)) x)]
    (cond
      (nil? x) true
      (boolean? x) x
      :else (let [[_ k] (re-matches #"&\{(.+)\}" (str x))
                  v (if k (get-in @(:tenant env) [:services :esv k]) x)]
              (not= "false" (str/lower-case (str v)))))))

(defn- pointer [p] (mapv keyword (remove str/blank? (str/split (str p) #"/"))))

(defn- mapping-script [env ctx depth mapping what cfg vars]
  (:value (run-script env ctx depth cfg (str "mapping " (:name mapping) " " what) vars)))

(defn- build-target
  "The target object a mapping makes from `source`: each property's condition, source, transform, default."
  [env ctx depth mapping source]
  (reduce (fn [t {:keys [condition transform default] :as p}]
            (if (and condition (not (mapping-script env ctx depth mapping (str "condition of " (:target p)) condition {:object source :linkQualifier "default"})))
              t
              (let [v (cond (not (str/blank? (:source p))) (get-in source (pointer (:source p)))
                              transform source)   ; no source: the transform sees the whole object
                    v (if transform (mapping-script env ctx depth mapping (str "transform of " (:target p)) transform {:source v :linkQualifier "default"}) v)
                    v (if (nil? v) default v)]
                (if (nil? v) t (assoc-in t (pointer (:target p)) v)))))
          {} (:properties mapping)))

(def ^:private default-actions
  {"CONFIRMED" "UPDATE" "FOUND" "UPDATE" "ABSENT" "CREATE" "AMBIGUOUS" "EXCEPTION" "MISSING" "EXCEPTION"
   "SOURCE_MISSING" "EXCEPTION" "UNQUALIFIED" "DELETE" "UNASSIGNED" "EXCEPTION" "LINK_ONLY" "EXCEPTION"
   "SOURCE_IGNORED" "IGNORE" "TARGET_IGNORED" "IGNORE" "FOUND_ALREADY_LINKED" "EXCEPTION" "ALL_GONE" "IGNORE"})

(defn- action-for [env ctx depth mapping situation vars]
  (let [a (:action (first (filter #(= situation (:situation %)) (:policies mapping))))]
    (cond
      (nil? a) (default-actions situation "IGNORE")
      (string? a) a
      :else (str (mapping-script env ctx depth mapping (str situation " action") a (assoc vars :situation situation))))))

(defn- correlate
  "Targets a correlation query finds for `source` (a script returning {_queryFilter ...}); none without one."
  [env ctx depth mapping source]
  (let [q (:correlationQuery mapping)
        q (if (sequential? q) (first q) q)]
    (when (and q (:source q))
      (let [params (mapping-script env ctx depth mapping "correlationQuery" q {:source source :linkQualifier "default"})]
        (:result (idm/query (:idm env) (store-type (:target mapping)) (update-vals (update-keys params name) str)))))))

(declare create update-obj delete-obj)

(defn- sync-one!
  "Implicit sync of one source object through one mapping. Returns {:mapping :situation :action ...}."
  [env ctx depth mapping source-id source]
  (let [links (:links env)
        lname (:name mapping)
        ttype (store-type (:target mapping))
        target-id (get-in @links [lname source-id])
        target (some->> target-id (idm/read-obj (:idm env) ttype))
        valid? (or (nil? source) (nil? (:validSource mapping))
                   (mapping-script env ctx depth mapping "validSource" (:validSource mapping) {:source source :linkQualifier "default"}))
        situation (cond
                    (nil? source) (when target-id "SOURCE_MISSING")
                    (not valid?) (when target "UNQUALIFIED")
                    target "CONFIRMED"
                    target-id "MISSING"
                    :else (let [found (correlate env ctx depth mapping source)]
                            (case (count found) 0 "ABSENT" 1 "FOUND" "AMBIGUOUS")))
        vars {:source source :target target :oldTarget target :linkQualifier "default"}
        action (when situation (action-for env ctx depth mapping situation vars))
        link! #(swap! links assoc-in [lname source-id] %)
        result {:mapping lname :situation situation :action action :sourceId source-id}]
    (case action
      "CREATE" (let [t (build-target env ctx depth mapping source)
                     t (if-let [s (:onCreate mapping)]
                         (or (:target (run-script env ctx depth s (str "mapping " lname " onCreate")
                                                  {:source source :target t :situation situation}))
                             t)
                         t)
                     saved (create env ctx (inc depth) ttype nil t)]
                 (link! (:_id saved))
                 (assoc result :targetId (:_id saved)))
      ("UPDATE" "LINK") (let [tid (or target-id (:_id (first (correlate env ctx depth mapping source))))
                              old (idm/read-obj (:idm env) ttype tid)
                              t (merge old (build-target env ctx depth mapping source))
                              t (if-let [s (and (= action "UPDATE") (:onUpdate mapping))]
                                  (or (:target (run-script env ctx depth s (str "mapping " lname " onUpdate")
                                                           {:source source :target t :oldTarget old :situation situation}))
                                      t)
                                  t)
                              saved (if (= action "LINK") old (update-obj env ctx (inc depth) ttype tid nil (dissoc t :_rev)))]
                          (link! tid)
                          (assoc result :targetId (:_id saved)))
      "DELETE" (do (when target (delete-obj env ctx (inc depth) ttype target-id))
                   (swap! links update lname dissoc source-id)
                   (assoc result :targetId target-id))
      "UNLINK" (do (swap! links update lname dissoc source-id) (assoc result :targetId target-id))
      "EXCEPTION" (assoc result :error (str "situation " situation " (action EXCEPTION)"))
      (nil "IGNORE" "ASYNC" "NOREPORT" "REPORT") result
      (assoc result :error (str "action " action " is not modelled")))))

(defn- sync-change!
  "After a write to `type`: run every enabled mapping whose source it is, and log what happened.
  A system object written by sync itself does not sync back (on the platform that would wait for
  liveSync); one written from outside (REST, a test) counts as a liveSync change at once."
  [env ctx depth type id obj]
  (when (and (< depth max-depth) (not (and (str/starts-with? type "system/") (pos? depth))))
    (doseq [m (:mappings @(:tenant env))
            :when (and (= (:source m) (source-res type)) (esv-bool env (:enableSync m)))]
      (let [r (try (sync-one! env ctx depth m id obj)
                   (catch clojure.lang.ExceptionInfo e {:mapping (:name m) :sourceId id :error (ex-message e)}))]
        (swap! (:sync-log env) conj (assoc r :at (str (java.time.Instant/now))))))))

(defn recon
  "POST /openidm/recon?_action=recon&mapping=<name>: every source object through the mapping."
  [env ctx mapping-name]
  (let [m (or (first (filter #(= mapping-name (:name %)) (:mappings @(:tenant env)))) (fail 404 (str "no mapping " mapping-name)))
        stype (store-type (:source m))
        before (count @(:sync-log env))]
    (doseq [[id o] (get @(:idm env) stype)]
      (sync-change! env ctx 0 stype id o))
    {:_id (str (random-uuid)) :mapping mapping-name :state "SUCCESS"
     :results (vec (filter #(= mapping-name (:mapping %)) (drop before @(:sync-log env))))}))

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

(declare recon)

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
      "recon" (recon env ctx (or (:mapping params) (:mapping content)))
      (fail 501 (str "action " action " on " resource " is not modelled")))))

;; ---- the dispatcher scripts call ------------------------------------------------------------

(defn- sha [alg v] (str/join (map #(format "%02x" %) (.digest (MessageDigest/getInstance alg) (.getBytes (str v) "UTF-8")))))

(defn dispatch
  "One openidm.* call from a script (or from REST, with depth 0)."
  [env ctx depth op {:keys [resource id content params fields rev ops] :as args}]
  (when (> depth max-depth) (fail 508 (str "scripts called openidm " max-depth " levels deep: a trigger loop?")))
  (let [[kind type oid] (split-resource resource)
        [type oid] (if (= kind "system")
                     (let [[ot id] (str/split (or oid "") #"/" 2)] [(str "system/" type "/" ot) id])
                     [type oid])
        managed! #(when-not (#{"managed" "system"} kind) (fail 501 (str op " on " resource " is not modelled (only managed/, system/ and endpoint/)")))
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
