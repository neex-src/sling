(ns sling.frodo
  "Read a Frodo export as the tenant, so the files a team already keeps in git are what the fake
  runs: `frodo config export -AxD <dir>` (the all-separate layout, realm/root-<realm>/... and
  global/...), or any folder of *.journey.json / *.script.json files, single-file exports included.

    journey/*.journey.json      trees, nodes, innerNodes and (in single-file exports) scripts
    script/*.script.json        metadata; the source is the file:// neighbour, a string or lines
    oauth2.app/*.json           OAuth2 clients (without secrets: those go in services.edn)
    global/variable/*.json      ESVs, seen by scripts as esv.a.b
    global/idm/managed/*.json   managed object schemas and their scripts (onCreate, postUpdate ...)
    global/idm/endpoint/*.json  custom endpoints (inline source, or a file:// neighbour)
    global/emailTemplate/*.json email templates (Email Suspend, external/email sendTemplate)
    global/sync/*.sync.json     sync mappings (also global/mapping/*.mapping.json)

  Also `coverage`: for each journey, which node types and scripts sling can run, which it
  cannot and why, so the cost of a real tenant can be read off its export before writing code."
  (:require [cheshire.core :as json]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [sling.engine :as engine]
            [sling.mfa]
            [sling.nodes]))

(defn- read-json [f] (json/parse-string (slurp f) true))

(defn- files-ending [dir suffix]
  (->> (file-seq (io/file dir))
       (filter #(and (.isFile %) (str/ends-with? (.getName %) suffix)))
       (sort-by #(.getPath %))))

(defn- in-realm?
  "Keep files of `realm` (and global ones) when the export has realm/ folders; keep all otherwise."
  [root realm f]
  (let [p (str (.relativize (.toPath (io/file root)) (.toPath f)))]
    (or (not (.exists (io/file root "realm")))
        (str/starts-with? p (str "realm/root-" realm "/"))
        (str/starts-with? p "global/"))))

(defn- source-of
  "Script text from an export: a file:// reference, lines, or (in journey files) a JSON-encoded string."
  [f script]
  (cond
    (and (string? script) (str/starts-with? script "\""))
    (let [v (try (json/parse-string script) (catch Exception _ script))] (if (sequential? v) (str/join "\n" v) v))
    (and (string? script) (str/starts-with? script "file://"))
    (let [g (io/file (.getParentFile f) (subs script 7))] (when (.exists g) (slurp g)))
    (sequential? script) (str/join "\n" script)
    (string? script) script))

(defn- script-entry [f m]
  {:meta (dissoc m :script) :source (or (source-of f (:script m)) "")})

(defn load-tenant
  "The export at `root` as a tenant map, the same shape sling.store/load-tenant returns, plus
  :clients {id export-config}, :managed-schemas {type schema} and :services seeded with the ESVs."
  [root realm]
  (let [keep? #(in-realm? root realm %)
        journeys (for [f (files-ending root ".journey.json") :when (keep? f)
                       [name j] (:trees (read-json f))]
                   [f (clojure.core/name name) j])
        scripts (concat
                 (for [f (files-ending root ".script.json") :when (keep? f)
                       [_ m] (:script (read-json f))]
                   [(:_id m) (script-entry f m)])
                 (for [[f _ j] journeys, [_ m] (:scripts j) :when (:script m)]
                   [(:_id m) (script-entry f m)]))
        variables (for [f (files-ending root ".variable.json") :when (keep? f)
                        [id v] (:variable (read-json f))]
                    [(str/replace (clojure.core/name id) "-" ".")
                     (or (:value v) (some-> (:valueBase64 v) (#(String. (.decode (java.util.Base64/getDecoder) ^String %) "UTF-8"))))])]
    {:dir (str root) :realm realm
     :trees (into {} (for [[_ n j] journeys] [n (:tree j)]))
     :nodes (into {} (for [[_ _ j] journeys, k [:nodes :innerNodes], [id cfg] (get j k)]
                       [(clojure.core/name id) cfg]))
     :scripts (into {} scripts)
     :clients (into {} (for [f (files-ending root ".oauth2.app.json") :when (keep? f)
                             [id c] (:application (read-json f))]
                         [(clojure.core/name id) c]))
     :managed-schemas (into {} (for [f (files-ending root ".managed.json") :when (keep? f)
                                     :let [m (read-json f)]
                                     o (or (get-in m [:idm :managed :objects]) (when (:name m) [m])
                                           (some-> (:idm m) vals first :objects))
                                     :when (:name o)]
                                 [(:name o) o]))
     :idm-endpoints (into {} (for [f (files-ending root ".idm.json") :when (keep? f)
                                   [id cfg] (:idm (read-json f))
                                   :let [id (subs (str id) 1)]
                                   :when (str/starts-with? id "endpoint/")]
                               [(subs id 9) (cond-> cfg (and (nil? (:source cfg)) (:file cfg))
                                              (assoc :source (source-of f (str "file://" (:file cfg)))))]))
     :trusted-issuers (into {} (for [f (files-ending root ".trustedJwtIssuer.json") :when (keep? f)
                                     [id t] (:trustedJwtIssuer (read-json f))]
                                 [(clojure.core/name id) t]))
     :mappings (let [named (into {} (for [f (concat (files-ending root ".sync.json") (files-ending root ".mapping.json"))
                                          :when (keep? f)
                                          :let [m (read-json f)
                                                m (if (:idm m) (first (vals (:idm m))) m)]
                                          :when (and (:name m) (:source m))]
                                      [(:name m) m]))]
                 (vec (vals named)))
     :email-templates (into {} (for [f (files-ending root ".emailTemplate.json") :when (keep? f)
                                     [id t] (:emailTemplate (read-json f))]
                                 [(clojure.core/name id) t]))
     :services {:esv (into {} variables) :default-journey "Login"}}))

;; ---- coverage ------------------------------------------------------------------------------

(def ^:private implemented
  (delay (set (remove #{:default} (keys (methods engine/run-node))))))

(def built-in #{"InnerTreeEvaluatorNode"})

(def ^:private legacy-marks
  [[#"\boutcome\s*=" "assigns `outcome` (legacy)"]
   [#"\bsharedState\b" "uses sharedState (legacy)"]
   [#"\btransientState\b" "uses transientState (legacy)"]
   [#"JavaImporter|Packages\.|\borg\.forgerock\.|\bjavax\." "uses Java classes"]])

(defn- script-report [t id]
  (if-let [{:keys [meta source]} (get-in t [:scripts id])]
    (let [legacy (for [[re why] legacy-marks :when (re-find re source)] why)
          bindings (sort (distinct (map second (re-seq #"\b(nodeState|callbacksBuilder|callbacks|action|httpClient|openidm|idRepository|systemEnv|requestHeaders|requestParameters|requestCookies|existingSession|logger|secrets|utils|jwtAssertion|jwtValidator|resumedFromSuspend|cookieName|realm|scriptName|require)\b" source))))]
      {:script (:name meta) :id id :language (:language meta) :evaluatorVersion (:evaluatorVersion meta)
       :bindings (vec bindings)
       :legacy? (= "1.0" (:evaluatorVersion meta))
       :java-classes (vec (sort (distinct (map second (re-seq #"\b((?:org|javax|com|java)\.[\w.]+\.[A-Z]\w*)" source)))))
       :runs? (= "JAVASCRIPT" (:language meta))
       :why (vec (concat (when (not= "JAVASCRIPT" (:language meta)) [(str "language " (:language meta))])
                         legacy))})
    {:id id :runs? false :why ["script not in the export"]}))

(defn coverage
  "Per journey: node types used (inner page nodes included), the ones missing, and its scripts."
  [t]
  (vec (for [[name tree] (sort-by key (:trees t))]
         (let [ids (map clojure.core/name (keys (:nodes tree)))
               cfgs (map #(get-in t [:nodes %]) ids)
               types (concat (map :nodeType (vals (:nodes tree)))
                             (for [c cfgs, child (:nodes c)] (:nodeType child)))
               scripts (distinct (concat (keep :script cfgs)
                                         (for [c cfgs, child (:nodes c)] (:script (get-in t [:nodes (:_id child)])))))
               scripts (map #(script-report t %) (remove nil? scripts))
               missing (sort (distinct (remove (into built-in @implemented) types)))
               inner (keep :tree cfgs)]
           {:journey name :node-types (vec (sort (distinct types))) :missing-nodes (vec missing)
            :inner-journeys (vec inner) :missing-inner (vec (remove (:trees t) inner))
            :scripts (vec scripts)
            :runnable? (and (empty? missing) (every? :runs? scripts) (every? (:trees t) inner))}))))

(defn print-coverage [t]
  (let [rows (coverage t)
        nodes (frequencies (mapcat :missing-nodes rows))
        scripts (distinct (mapcat :scripts rows))]
    (doseq [{:keys [journey runnable? missing-nodes scripts missing-inner]} rows]
      (println (format "%-24s %s" journey (if runnable? "RUNS" "BLOCKED"))
               (str/join "; " (concat (when (seq missing-nodes) [(str "nodes: " (str/join ", " missing-nodes))])
                                      (when (seq missing-inner) [(str "inner journeys missing: " (str/join ", " missing-inner))])
                                      (for [s scripts :when (not (:runs? s))] (str "script " (pr-str (:script s)) ": " (str/join ", " (:why s))))))))
    (println)
    (println (count (filter :runnable? rows)) "of" (count rows) "journeys run as exported.")
    (println "missing node types, by number of journeys that need them:")
    (doseq [[n c] (sort-by (comp - val) nodes)] (println (format "  %3d  %s" c n)))
    (println "decision scripts:" (count scripts) "-" (count (filter :runs? scripts)) "next-generation ones run,"
             (count (remove :runs? scripts)) "do not (" (str/join ", " (distinct (mapcat :why (remove :runs? scripts)))) ")")))

;; ---- IDM coverage --------------------------------------------------------------------------

(def ^:private modelled-actions #{"external/rest call" "external/email send" "external/email sendTemplate"})

(defn- idm-script-report
  "What one IDM script needs: language, the openidm actions it calls, Java or require use."
  [what {:keys [type source file expressionTree]}]
  (let [src (or source "")
        file (when-not expressionTree file)
        actions (for [[_ res act] (re-seq #"openidm\.action\(\s*[\"']([^\"']+)[\"']\s*,\s*[\"']([^\"']+)[\"']" src)]
                  (str (str/replace res #"/[^/]*$" (if (str/starts-with? res "external/") (str "/" (last (str/split res #"/"))) "")) " " act))
        resources (distinct (map second (re-seq #"openidm\.\w+\(\s*[\"']([a-z]+/[\w-]+)" src)))
        why (concat (when (and type (not= type "text/javascript")) [(str "language " type)])
                    (when (and (str/blank? src) file) [(str "source in file " file ", not in the export")])
                    (for [a (distinct actions) :when (not (modelled-actions a))
                          :when (not (str/starts-with? a "endpoint"))] (str "action " a))
                    (for [r resources :when (not (re-find #"^(managed|system|endpoint|external)/" r))] (str "resource " r))
                    (when (re-find #"\brequire\(" src) ["require()"])
                    (when (re-find #"\b(Packages|java\.|org\.forgerock\.)" src) ["Java classes"]))]
    {:what what :runs? (empty? why) :why (vec (distinct why))}))

(defn idm-coverage [t]
  (concat
   (for [[n cfg] (sort-by key (:idm-endpoints t))] (idm-script-report (str "endpoint/" n) cfg))
   (for [[type o] (sort-by key (:managed-schemas t))
         [hook cfg] (sort-by key (select-keys o [:onCreate :postCreate :onUpdate :postUpdate :onDelete :postDelete
                                                 :onRead :onRetrieve :onValidate :onStore :onSync]))]
     (idm-script-report (str "managed/" type " " (name hook)) cfg))
   (for [m (sort-by :name (:mappings t))
         [what cfg] (concat (keep (fn [k] (when-let [c (get m k)] [(name k) (if (sequential? c) (first c) c)]))
                                  [:validSource :validTarget :onCreate :onUpdate :onDelete :onLink :onUnlink :result :correlationQuery])
                            (for [p (:properties m) k [:transform :condition] :when (map? (get p k))] [(str (name k) " of " (:target p)) (get p k)])
                            (for [p (:policies m) :when (map? (:action p))] [(str (:situation p) " action") (:action p)]))]
     (idm-script-report (str "mapping " (:name m) " " what) cfg))))

(defn print-idm-coverage [t]
  (let [rows (idm-coverage t)]
    (doseq [{:keys [what runs? why]} rows]
      (println (format "%-60s %s" what (if runs? "RUNS" (str "BLOCKED " (str/join "; " why))))))
    (println)
    (println (count (filter :runs? rows)) "of" (count rows) "IDM scripts (endpoints, managed object scripts, mapping scripts) run here.")
    (println "mappings:" (str/join ", " (for [m (:mappings t)] (str (:name m) " (" (:source m) " -> " (:target m) ")"))))))

(defn -main [root & [realm]]
  (let [t (load-tenant root (or realm "alpha"))]
    (print-coverage t)
    (println)
    (print-idm-coverage t))
  (shutdown-agents))
