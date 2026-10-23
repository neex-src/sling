(ns sling.engine
  "Walks a journey the way the docs describe: from entryNodeId along `connections`, one node
  at a time, pausing whenever a node asks the client for callbacks and picking up again when
  the answers arrive. A session is plain data, so a test can hold one, inspect it and resume it.

  Node types implemented: UsernameCollectorNode, PasswordCollectorNode, DataStoreDecisionNode,
  ScriptedDecisionNode, InnerTreeEvaluatorNode, plus the Success and Failure terminals.
  Any other nodeType fails the journey and says so: nothing is silently skipped.

  Results: {:status :callbacks|:success|:failure, :callbacks [wire], :session s, :reason str}.
  Wire callbacks have the shape /json/authenticate sends (type, output[], input[] named IDTokenN)."
  (:require [sling.idm :as idm]
            [sling.script :as script]))

(def success-id "70e691a5-1e33-4ac3-a356-e7b6d60d92e0")
(def failure-id "e301438c-0bd0-429c-ab0c-66126501069a")
(def ^:private step-limit 200)

;; ---- callbacks on the wire -------------------------------------------------------------------

(defn- out [& kvs] (mapv (fn [[k v]] {:name k :value v}) (partition 2 kvs)))

(defn- wire-one [{:keys [type args]} n]
  (let [in (fn [v] [{:name (str "IDToken" n) :value v}])]
    (case type
      "NameCallback" {:type type :output (out "prompt" (:prompt args)) :input (in (:default args))}
      "PasswordCallback" {:type type :output (out "prompt" (:prompt args)) :input (in "")}
      "TextInputCallback" {:type type :output (out "prompt" (:prompt args) "defaultText" (:default args)) :input (in (:default args))}
      "TextOutputCallback" {:type type :output (out "message" (:message args) "messageType" (str (:messageType args)))}
      "HiddenValueCallback" {:type type :output (out "value" (:value args) "id" (:id args)) :input (in (:value args))}
      "ChoiceCallback" {:type type :output (out "prompt" (:prompt args) "choices" (:choices args) "defaultChoice" (:defaultChoice args))
                        :input (in (:defaultChoice args))}
      "ConfirmationCallback" {:type type :output (out "prompt" (:prompt args) "messageType" 0 "options" (:options args)
                                                    "optionType" -1 "defaultOption" (or (:defaultOption args) 0))
                              :input (in (or (:defaultOption args) 0))}
      ;; the platform callbacks (ValidatedCreate*, *AttributeInputCallback ...): output as the node gives it
      (cond-> {:type type :output (mapv (fn [[k v]] {:name (name k) :value v}) (:output args))}
        (not (:output-only args)) (assoc :input (in (:default args)))))))

(defn- wire [specs]
  (loop [specs specs n 1 acc []]
    (if-let [s (first specs)]
      (let [w (wire-one s n)]
        (recur (rest specs) (if (:input w) (inc n) n) (conj acc w)))
      acc)))

(defn- answers
  "Pair the client's answers with the callbacks we asked for, in order. Output-only ones carry none."
  [pending client]
  (vec (for [[spec cb] (map vector pending client)
             :when (not (or (= "TextOutputCallback" (:type spec)) (get-in spec [:args :output-only])))]
         (cond-> {:type (:type spec) :value (some-> cb :input first :value)}
           (= "HiddenValueCallback" (:type spec)) (assoc :id (get-in spec [:args :id]))
           (:child spec) (assoc :child (:child spec))))))

;; ---- nodes -----------------------------------------------------------------------------------

(defmulti run-node
  "Run one node. ctx: {:type :config :tenant :session :inputs}. Returns one of
  {:outcome s} | {:callbacks [spec]} | {:error s}, and may add :shared :transient :props :message."
  :type)

(defmethod run-node :default [{:keys [type]}]
  {:error (str "node type " type " is not implemented in sling")})

(defmethod run-node "UsernameCollectorNode" [{:keys [inputs]}]
  (if (seq inputs)
    {:outcome "outcome" :shared {"username" (:value (first inputs))}}
    {:callbacks [{:type "NameCallback" :args {:prompt "User Name"}}]}))

(defmethod run-node "PasswordCollectorNode" [{:keys [inputs]}]
  (if (seq inputs)
    {:outcome "outcome" :transient {"password" (:value (first inputs))}}
    {:callbacks [{:type "PasswordCallback" :args {:prompt "Password"}}]}))

(defmethod run-node "DataStoreDecisionNode" [{:keys [tenant session]}]
  (let [user (get-in session [:shared "username"])
        pw (get-in session [:transient "password"])
        {:keys [idm realm]} (:services tenant)
        known (if idm
                (idm/find-by idm (str realm "_user") :userName user)
                (get-in tenant [:services :users user]))]
    {:outcome (if (and known (some? pw) (= pw (:password known))) "true" "false")}))

(defmethod run-node "ScriptedDecisionNode" [{:keys [tenant session config inputs]}]
  (if-let [{:keys [source]} (get-in tenant [:scripts (:script config)])]
    (let [r (script/run-script source
                               {:shared (:shared session) :transient (:transient session)
                                :request (:request session) :callbacks inputs}
                               (:services tenant))
          allowed (set (or (:outcomes config) ["true" "false"]))
          a (:action r)]
      (cond
        (:error r) {:error (:error r) :logs (:logs r)}
        (and (:outcome r) (not (allowed (:outcome r))))
        {:error (str "script went to outcome " (pr-str (:outcome r)) ", node allows " (pr-str (sort allowed)))
         :logs (:logs r)}
        (:outcome r) {:outcome (:outcome r) :shared (:shared r) :transient (:transient r) :logs (:logs r)
                      :props (:sessionProps a) :message (:errorMessage a)}
        (seq (:callbacks r)) {:callbacks (:callbacks r) :shared (:shared r) :transient (:transient r)}
        :else {:error "script finished without action.goTo(...) and without a callback" :logs (:logs r)}))
    {:error (str "script " (pr-str (:script config)) " not found")}))

;; ---- the walk --------------------------------------------------------------------------------

(defn- tree-of [t s] (get-in t [:trees (:journey s)]))

(defn- fail [s reason] {:status :failure :reason reason :session s})

(defn- goto-outcome
  "Follow `outcome` from the current node. Returns the session at the next node, or ::dead-end."
  [t s outcome]
  (if-let [nxt (get-in (tree-of t s) [:nodes (keyword (:node s)) :connections (keyword outcome)])]
    (assoc s :node nxt)
    ::dead-end))

(defn- advance [t s inputs]
  (loop [s s inputs inputs steps 0]
    (let [node (:node s)]
      (cond
        (> steps step-limit) (fail s (str "stopped after " step-limit " steps: loop in journey?"))

        (#{success-id failure-id} node)
        (let [outcome (if (= node success-id) "true" "false")]
          (if-let [frame (peek (:stack s))]
            (let [s' (-> s (assoc :journey (:journey frame) :node (:node frame)) (update :stack pop))
                  nxt (goto-outcome t s' outcome)]
              (if (= ::dead-end nxt)
                (fail s' (str "inner journey ended " outcome " but node " (:node frame) " has no such connection"))
                (recur nxt nil (inc steps))))
            (if (= node success-id)
              {:status :success :session s}
              (fail s (str "reached the Failure node after " (pr-str (:node (peek (:trace s))))
                           (when-let [m (:error-message s)] (str ": " m)))))))

        :else
        (let [nd (get-in (tree-of t s) [:nodes (keyword node)])
              type (:nodeType nd)
              cfg (get-in t [:nodes node])
              name (or (:displayName nd) node)]
          (if (nil? nd)
            (fail s (str "node " node " is not in journey " (:journey s)))
            (if (= type "InnerTreeEvaluatorNode")
              (if-let [inner (get-in t [:trees (:tree cfg)])]
                (recur (-> s
                           (update :stack conj {:journey (:journey s) :node node})
                           (assoc :journey (:tree cfg) :node (:entryNodeId inner)))
                       nil (inc steps))
                (fail s (str "inner journey " (pr-str (:tree cfg)) " does not exist")))
              (let [r (run-node {:type type :config cfg :tenant t :session s :inputs inputs})]
                (cond
                  (:error r) (fail (update s :trace (fnil conj []) {:journey (:journey s) :node name :error (:error r)})
                                   (str name ": " (:error r)))

                  (:callbacks r)
                  (let [s' (-> s (update :shared merge (:shared r)) (update :transient merge (:transient r))
                               (assoc :pending (:callbacks r)))]
                    {:status :callbacks :callbacks (wire (:callbacks r)) :session s'})

                  :else
                  (let [s' (-> s
                               (update :shared merge (:shared r))
                               (update :transient merge (:transient r))
                               (update :props merge (:props r))
                               (cond-> (:message r) (assoc :error-message (:message r)))
                               (assoc :pending nil)
                               (update :trace (fnil conj [])
                                       (cond-> {:journey (:journey s) :node name :outcome (:outcome r)}
                                         (seq (:logs r)) (assoc :logs (:logs r)))))
                        nxt (goto-outcome t s' (:outcome r))]
                    (if (= ::dead-end nxt)
                      (fail s' (str name ": no connection for outcome " (pr-str (:outcome r))))
                      (recur nxt nil (inc steps)))))))))))))

(defn start
  "Begin `journey` for a request {:headers {name [v]} :parameters {name [v]} :cookies {name v}}."
  [t journey request]
  (let [tree (get-in t [:trees journey])]
    (if (or (nil? tree) (false? (:enabled tree)))
      (fail nil "Tree does not exist")
      (advance t {:journey journey :node (:entryNodeId tree) :stack [] :shared {} :transient {} :props {}
                  :request (merge {:headers {} :parameters {} :cookies {}} request) :trace []}
               nil))))

(defn resume
  "Continue a session that is waiting for callbacks. `client` is the callbacks array the client posted back."
  [t session client]
  (advance t session (answers (:pending session) client)))

(defn answer
  "Test helper: fill the first input of each wire callback in order from `values`, in the client's JSON shape."
  [wire-callbacks values]
  (loop [cbs wire-callbacks vs values acc []]
    (if-let [cb (first cbs)]
      (if (seq (:input cb))
        (recur (rest cbs) (rest vs) (conj acc (assoc-in cb [:input 0 :value] (first vs))))
        (recur (rest cbs) vs (conj acc cb)))
      acc)))
