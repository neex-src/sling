(ns sling.frodo
  "Read a Frodo export as the tenant, so the files a team already keeps in git are what the fake
  runs: `frodo config export -AxD <dir>` (the all-separate layout, realm/root-<realm>/... and
  global/...), or any folder of *.journey.json / *.script.json files, single-file exports included.

    journey/*.journey.json      trees, nodes, innerNodes and (in single-file exports) scripts
    script/*.script.json        metadata; the source is the file:// neighbour, a string or lines
    oauth2.app/*.json           OAuth2 clients (without secrets: those go in services.edn)
    global/variable/*.json      ESVs, seen by scripts as esv.a.b
    global/idm/managed/*.json   managed object schemas (the Attribute Collector reads types)

  Also `coverage`: for each journey, which node types and scripts sling can run, which it
  cannot and why, so the cost of a real tenant can be read off its export before writing code."
  (:require [cheshire.core :as json]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [sling.engine :as engine]
            [sling.nodes]))

(defn- read-json [f] (json/parse-string (slurp f) true))

(defn- files-ending [dir suffix]
  (->> (file-seq (io/file dir))
       (filter #(and (.isFile %) (str/ends-with? (.getName %) suffix)))
       (sort-by #(.getPath %))))

(defn- in-realm?
  "Keep files of `realm` (and global ones) when the export has realm/ folders; keep all otherwise."
  [root realm f]
  (let [p (.getPath (.relativize (.toPath (io/file root)) (.toPath f)))]
    (or (not (.exists (io/file root "realm")))
        (str/starts-with? p (str "realm/root-" realm "/"))
        (str/starts-with? p "global/"))))

(defn- source-of [f script]
  (cond
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
       :runs? (and (= "JAVASCRIPT" (:language meta)) (not= "1.0" (:evaluatorVersion meta)) (empty? legacy))
       :why (vec (concat (when (not= "JAVASCRIPT" (:language meta)) [(str "language " (:language meta))])
                         (when (= "1.0" (:evaluatorVersion meta)) ["legacy (1.0) script engine"])
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

(defn -main [root & [realm]]
  (print-coverage (load-tenant root (or realm "alpha")))
  (shutdown-agents))
