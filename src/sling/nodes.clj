(ns sling.nodes
  "The platform nodes a stock Advanced Identity Cloud journey is made of, modelled from the node
  reference, working on the IDM store the server shares (tenant :services :idm):

    ZeroPageLoginNode  PageNode  ValidatedUsernameNode  ValidatedPasswordNode  IdentityStoreDecisionNode
    AttributeCollectorNode  PatchObjectNode  CreateObjectNode  IdentifyExistingUserNode
    IncrementLoginCountNode  LoginCountDecisionNode  QueryFilterDecisionNode
    AttributePresentDecisionNode  AccountActiveDecisionNode  RetryLimitDecisionNode
    AccountLockoutNode  ChoiceCollectorNode  MessageNode  SetSessionPropertiesNode

  Conventions taken from the docs: the username goes to shared state `username`, the password to
  transient `password`, collected profile fields to `objectAttributes` (shared, the password in the
  transient copy), the identified user's id to shared `_id`. The login count is kept on the user
  under _meta/loginCount (the real property is not in the docs); retries live in shared
  `<nodeId>.retryCount`."
  (:require [clojure.string :as str]
            [sling.engine :as engine]
            [sling.idm :as idm]))

(defn- idm-of [tenant] (get-in tenant [:services :idm]))

(defn- identity-type [tenant session cfg]
  (let [r (or (:identityResource cfg) (get-in tenant [:trees (:journey session) :identityResource]))]
    (if r (str/replace r #"^managed/" "") (str (get-in tenant [:services :realm] "alpha") "_user"))))

(defn- obj-attrs [session] (merge (get-in session [:shared "objectAttributes"]) (get-in session [:transient "objectAttributes"])))

(defn- the-user
  "The user the journey has identified so far: by shared _id, else by `attr` (userName by default)."
  [{:keys [tenant session config]}]
  (let [store (idm-of tenant)
        type (identity-type tenant session config)
        attr (or (:identityAttribute config) "userName")
        v (or (get (obj-attrs session) (keyword attr)) (get (obj-attrs session) attr)
              (when (= attr "userName") (get-in session [:shared "username"])))]
    (when store
      (or (some->> (get-in session [:shared "_id"]) (idm/read-obj store type))
          (when v (idm/find-by store type (keyword attr) v))))))

(defn- router-call
  "Write through the IDM router when the server has one, so the managed object scripts run;
  straight to the store otherwise. A refusal (onValidate throwing, say) is nil."
  [tenant op args direct]
  (if-let [r (get-in tenant [:services :openidm])]
    (try (r op args) (catch clojure.lang.ExceptionInfo _ nil))
    (direct)))

(defn- no-store [] {:error "this node needs the IDM store: run it through the server, or seed :idm"})

(defn- shared-attrs [session m] {"objectAttributes" (merge (get-in session [:shared "objectAttributes"]) m)})

;; ---- page ----------------------------------------------------------------------------------

(defmethod engine/run-node "PageNode" [{:keys [config tenant session all-inputs]}]
  (let [children (:nodes config)
        by-child (group-by :child all-inputs)]
    (loop [i 0 s session cbs [] out {:shared {} :transient {}} outcome nil]
      (if (= i (count children))
        (if (seq cbs) (assoc out :callbacks cbs) (assoc out :outcome (or outcome "outcome")))
        (let [{:keys [_id nodeType]} (nth children i)
              r (engine/run-node {:type nodeType :config (get-in tenant [:nodes _id]) :tenant tenant :session s
                                  :inputs (vec (remove :output (get by-child i))) :all-inputs (vec (get by-child i))})
              s' (-> s (update :shared merge (:shared r)) (update :transient merge (:transient r)))
              out' (-> out (update :shared merge (:shared r)) (update :transient merge (:transient r))
                       (update :props merge (:props r)))]
          (cond
            (:error r) r
            (:callbacks r) (recur (inc i) s' (into cbs (map #(assoc % :child i) (:callbacks r))) out' outcome)
            :else (recur (inc i) s' cbs out' (:outcome r))))))))

;; ---- collectors ----------------------------------------------------------------------------

(defmethod engine/run-node "ValidatedUsernameNode" [{:keys [config session inputs]}]
  (let [attr (or (:usernameAttribute config) "userName")]
    (if (seq inputs)
      (let [u (str (:value (first inputs)))]
        {:outcome "outcome" :shared (merge {"username" u} (shared-attrs session {(keyword attr) u}))})
      {:callbacks [(if (:validateInput config)
                     {:type "ValidatedCreateUsernameCallback"
                      :args {:output {:policies {} :failedPolicies [] :validateOnly false :prompt "Username"}}}
                     {:type "NameCallback" :args {:prompt "User Name"}})]})))

(defmethod engine/run-node "ValidatedPasswordNode" [{:keys [config session inputs]}]
  (let [attr (or (:passwordAttribute config) "password")]
    (if (seq inputs)
      (let [p (str (:value (first inputs)))]
        {:outcome "outcome"
         :transient {"password" p "objectAttributes" (merge (get-in session [:transient "objectAttributes"]) {(keyword attr) p})}})
      {:callbacks [(if (:validateInput config)
                     {:type "ValidatedCreatePasswordCallback"
                      :args {:output {:echoOn false :policies {} :failedPolicies [] :validateOnly false :prompt "Password"}}}
                     {:type "PasswordCallback" :args {:prompt "Password"}})]})))

(defn- schema-type [tenant type pointer]
  (let [path (interleave (repeat :properties) (map keyword (str/split pointer #"/")))]
    (get-in tenant (concat [:managed-schemas type :schema] path [:type]))))

(defmethod engine/run-node "AttributeCollectorNode" [{:keys [config tenant session inputs]}]
  (let [type (identity-type tenant session config)
        attrs (:attributesToCollect config)
        kind #(case (schema-type tenant type %) "boolean" :boolean "number" :number :string)]
    (if (seq inputs)
      (let [coerce (fn [a v] (case (kind a)
                               :boolean (contains? #{true "true"} v)
                               :number (if (number? v) v (parse-double (str v)))
                               v))
            collected (reduce (fn [m [a in]] (assoc-in m (map keyword (str/split a #"/")) (coerce a (:value in))))
                              {} (map vector attrs inputs))]
        {:outcome "outcome" :shared (shared-attrs session collected)})
      {:callbacks (vec (for [a attrs]
                         {:type (case (kind a) :boolean "BooleanAttributeInputCallback"
                                      :number "NumberAttributeInputCallback" "StringAttributeInputCallback")
                          :args {:output {:name a :prompt a :required (boolean (:required config)) :policies {}
                                          :failedPolicies [] :validateOnly false
                                          :value (get-in (obj-attrs session) (map keyword (str/split a #"/")) "")}
                                 :default (if (= :boolean (kind a)) false "")}}))})))

(defmethod engine/run-node "ChoiceCollectorNode" [{:keys [config inputs]}]
  (let [choices (vec (:choices config))]
    (if (seq inputs)
      (let [i (let [v (:value (first inputs))] (if (number? v) (long v) (parse-long (str v))))]
        {:outcome (get choices i (:defaultChoice config))})
      {:callbacks [{:type "ChoiceCallback" :args {:prompt (:prompt config) :choices choices
                                                   :defaultChoice (max 0 (.indexOf choices (:defaultChoice config)))}}]})))

(defn- localized [m] (if (map? m) (or (:en m) (first (vals m))) m))

(defmethod engine/run-node "MessageNode" [{:keys [config inputs]}]
  (if (seq inputs)
    (let [yes? (contains? #{0 "0"} (:value (first inputs)))]
      (cond-> {:outcome (if yes? "true" "false")}
        (:stateField config) (assoc :shared {(:stateField config) (if yes? 0 1)})))
    {:callbacks [{:type "TextOutputCallback" :args {:messageType 0 :message (localized (:message config))}}
                 {:type "ConfirmationCallback" :args {:prompt "" :options [(or (localized (:messageYes config)) "Yes")
                                                                         (or (localized (:messageNo config)) "No")]}}]}))

;; ---- identity ------------------------------------------------------------------------------

(defmethod engine/run-node "IdentityStoreDecisionNode" [{:keys [tenant session config] :as ctx}]
  (if-not (idm-of tenant)
    (no-store)
    (let [u (idm/find-by (idm-of tenant) (identity-type tenant session config) :userName (get-in session [:shared "username"]))
          pw (get-in session [:transient "password"])]
      (cond
        (or (nil? u) (nil? pw) (not= pw (:password u))) {:outcome "FALSE"}
        (not= "active" (or (:accountStatus u) "active")) {:outcome "LOCKED"}
        :else {:outcome "TRUE" :shared {"_id" (:_id u)}}))))

(defmethod engine/run-node "IdentifyExistingUserNode" [{:keys [tenant session config]}]
  (if-not (idm-of tenant)
    (no-store)
    (let [attr (or (:identityAttribute config) "mail")
          v (or (get (obj-attrs session) (keyword attr)) (get-in session [:shared attr]))
          u (when v (idm/find-by (idm-of tenant) (identity-type tenant session config) (keyword attr) v))]
      (if u
        {:outcome "true" :shared (merge {"_id" (:_id u) "username" (:userName u)}
                                        (shared-attrs session {:userName (:userName u)}))}
        {:outcome "false"}))))

(defmethod engine/run-node "AttributePresentDecisionNode" [{:keys [config] :as ctx}]
  (let [u (the-user ctx)]
    {:outcome (if (and u (some? (get-in u (map keyword (str/split (:presentAttribute config) #"/"))))) "true" "false")}))

(defmethod engine/run-node "AccountActiveDecisionNode" [ctx]
  (let [u (the-user ctx)]
    {:outcome (if (and u (= "active" (:accountStatus u))) "true" "false")}))

(defmethod engine/run-node "QueryFilterDecisionNode" [{:keys [config] :as ctx}]
  (if-let [u (the-user ctx)]
    {:outcome (if (idm/matches? (idm/parse-filter (:queryFilter config)) u) "true" "false")}
    {:outcome "false"}))

(defmethod engine/run-node "PatchObjectNode" [{:keys [tenant session config] :as ctx}]
  (let [u (the-user ctx)
        ignored (set (map keyword (:ignoredFields config)))
        changes (apply dissoc (obj-attrs session) ignored)]
    (let [type (identity-type tenant session config)
          ops (vec (for [[k v] changes] {:operation "replace" :field (str "/" (name k)) :value v}))]
      (if (and u (idm-of tenant)
               (router-call tenant "patch" {:resource (str "managed/" type "/" (:_id u)) :ops ops}
                            #(idm/patch! (idm-of tenant) type (:_id u) ops)))
        {:outcome "PATCHED"}
        {:outcome "FAILURE"}))))

(defmethod engine/run-node "CreateObjectNode" [{:keys [tenant session config]}]
  (if-let [store (idm-of tenant)]
    (let [attrs (obj-attrs session)
          type (identity-type tenant session config)]
      (if (or (nil? (:userName attrs)) (idm/find-by store type :userName (:userName attrs)))
        {:outcome "FAILURE"}
        (if-let [u (router-call tenant "create" {:resource (str "managed/" type) :content (merge {:accountStatus "active"} attrs)}
                                #(idm/create! store type (merge {:accountStatus "active"} attrs)))]
          {:outcome "CREATED" :shared {"_id" (:_id u) "username" (:userName u)}}
          {:outcome "FAILURE"})))
    (no-store)))

(defmethod engine/run-node "IncrementLoginCountNode" [{:keys [tenant session config] :as ctx}]
  (when-let [u (the-user ctx)]
    (idm/patch! (idm-of tenant) (identity-type tenant session config) (:_id u)
                [{:operation "replace" :field "/_meta/loginCount" :value (inc (or (get-in u [:_meta :loginCount]) 0))}]))
  {:outcome "outcome"})

(defmethod engine/run-node "LoginCountDecisionNode" [{:keys [config] :as ctx}]
  (let [n (or (get-in (the-user ctx) [:_meta :loginCount]) 0)
        amount (or (:amount config) 1)]
    {:outcome (if (if (= "EVERY" (:interval config)) (and (pos? n) (zero? (mod n amount))) (= n amount)) "true" "false")}))

(defmethod engine/run-node "RetryLimitDecisionNode" [{:keys [config session]}]
  (let [k (str (:_id config) ".retryCount")
        n (inc (or (get-in session [:shared k]) 0))]
    {:outcome (if (< n (or (:retryLimit config) 3)) "Retry" "Reject") :shared {k n}}))

(defmethod engine/run-node "AccountLockoutNode" [{:keys [tenant session config] :as ctx}]
  (when-let [u (the-user ctx)]
    (idm/patch! (idm-of tenant) (identity-type tenant session config) (:_id u)
                [{:operation "replace" :field "/accountStatus" :value (if (= "UNLOCK" (:lockAction config)) "active" "inactive")}]))
  {:outcome "outcome"})

(defmethod engine/run-node "SetSessionPropertiesNode" [{:keys [config]}]
  {:outcome "outcome" :props (into {} (map (fn [[k v]] [(name k) (str v)]) (:properties config)))})

;; ---- zero page login -----------------------------------------------------------------------

(defmethod engine/run-node "ZeroPageLoginNode" [{:keys [config session]}]
  (let [header (fn [name] (get-in session [:request :headers (str/lower-case name)]))
        users (header (or (:usernameHeader config) "X-OpenAM-Username"))
        passwords (header (or (:passwordHeader config) "X-OpenAM-Password"))
        referer (first (header "Referer"))
        referer-ok? (or (not (false? (:allowWithoutReferer config)))
                        (and referer (some #{referer} (:referrerWhiteList config))))]
    (cond
      (not (and (seq users) (seq passwords) referer-ok?)) {:outcome "noCredentials"}
      (or (next users) (next passwords))
      {:error (str "Expecting only one header value for username and/or password but size is "
                   (max (count users) (count passwords)) ".")}
      :else {:outcome "hasCredentials" :shared {"username" (first users)} :transient {"password" (first passwords)}})))
