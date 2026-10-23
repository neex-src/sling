(ns sling.frodowrite
  "Write changes back into the Frodo export the tenant was loaded from (serve --write), so a PUT
  against the fake (from `frodo journey import`, `frodo idm import`, a deploy script, a test) shows
  up as `git diff` in the export, in Frodo's own file format and layout:

    journey    the file the journey came from (other journeys in it untouched), its tree, nodes
               and page-node children; script copies a single-file export carries are refreshed
    script     its .script.json (and the .js beside it when the source was extracted)
    endpoint, managed object, mapping, other IDM config   their file; scripts Frodo extracted into
               .js files stay extracted, inline ones stay inline
    ESV        global/variable/<id>.variable.json

  Files keep their meta block. Something new goes where `frodo config export -AxD` would put it.
  Fields Frodo strips on export (_rev, lastModifiedBy, createdBy ...) are stripped here too, so
  putting back what was read leaves every byte as it was."
  (:require [cheshire.core :as json]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.walk :as walk]
            [sling.frodojson :as fj]))

(def ^:private volatile-keys
  #{:_rev :lastModifiedBy :lastModifiedDate :modified :modifiedDate :lastChangeDate :lastChangedBy
    :lastChanged :createdBy :creationDate :createdDate})

(defn- strip [x]
  (walk/postwalk #(if (map? %) (apply dissoc % volatile-keys) %) x))

(defn- read-json [f] (when (.exists (io/file f)) (json/parse-string (slurp f) true)))

(defn- write-json! [f x]
  (io/make-parents f)
  (let [text (fj/file-text x)]
    (when-not (= text (when (.exists (io/file f)) (slurp f)))
      (spit f text))))

(defn- write-text! [f s]
  (io/make-parents f)
  (when-not (= s (when (.exists (io/file f)) (slurp f))) (spit f s)))

(defn- realm-dir [root realm]
  (if (.exists (io/file root "realm")) (io/file root "realm" (str "root-" realm)) (io/file root)))

(defn- global-dir [root] (if (.exists (io/file root "realm")) (io/file root "global") (io/file root)))

(defn- file-name [s] (str/replace (str s) #"[\s/\\:*?\"<>|]+" "-"))

;; ---- keeping extracted scripts extracted -----------------------------------------------------

(defn- refs
  "Paths in `x` to script configs whose source is a file:// reference, with the reference."
  ([x] (refs x []))
  ([x path]
   (cond
     (and (map? x) (string? (:source x)) (str/starts-with? (:source x) "file://")) [[path (:source x)]]
     (map? x) (mapcat (fn [[k v]] (refs v (conj path k))) x)
     (sequential? x) (mapcat (fn [i v] (refs v (conj path i))) (range) x)
     :else [])))

(defn- extract-like
  "`new` with each script source that `old` kept in a file written to that file again (next to
  `f`) and replaced by the reference."
  [f old new]
  (reduce (fn [x [path ref]]
            (let [v (get-in x path)]
              (if (and (map? v) (string? (:source v)) (not (str/starts-with? (:source v) "file://")))
                (do (write-text! (io/file (.getParentFile (io/file f)) (subs ref 7)) (:source v))
                    (assoc-in x (conj path :source) ref))
                x)))
          new (refs old)))

;; ---- AM: journeys and scripts ------------------------------------------------------------

(defn- script-text [{:keys [source]}] source)

(defn write-journey!
  "Write journey `name` (tree + its nodes) into its file. `files` is the provenance index."
  [root realm t files name]
  (let [tree (get-in t [:trees name])
        f (or (get-in files [:tree name]) (io/file (realm-dir root realm) "journey" (str (file-name name) ".journey.json")))
        raw (or (read-json f) {})
        k (keyword name)
        old (get-in raw [:trees k] {})
        ids (map clojure.core/name (keys (:nodes tree)))
        node (fn [id] (strip (get-in t [:nodes id])))
        children (for [id ids, c (:nodes (get-in t [:nodes id]))] (:_id c))
        scripts (into {} (for [[sid s] (:scripts old)
                               :let [cur (get-in t [:scripts (clojure.core/name sid)])]]
                           [sid (if cur (assoc (strip (:meta cur)) :script (fj/stringify (script-text cur))) s)]))
        entry (merge {:circlesOfTrust {} :emailTemplates {} :saml2Entities {} :scripts {} :socialIdentityProviders {} :themes []}
                     old
                     {:tree (strip (dissoc tree :_rev))
                      :nodes (into {} (for [id ids :let [n (node id)] :when n] [(keyword id) n]))
                      :innerNodes (into {} (for [id children :let [n (node id)] :when n] [(keyword id) n]))
                      :scripts scripts})]
    (write-json! f (assoc-in raw [:trees k] entry))
    (assoc-in files [:tree name] (io/file f))))

(defn journeys-with-node
  "Names of the journeys that use node `id`, directly or inside a page node."
  [t id]
  (for [[n tree] (:trees t)
        :let [ids (set (map clojure.core/name (keys (:nodes tree))))]
        :when (or (ids id) (some #(some #{id} (map :_id (:nodes (get-in t [:nodes %])))) ids))]
    n))

(defn write-script!
  [root realm t files id]
  (let [{:keys [meta source]} (get-in t [:scripts id])
        f (or (get-in files [:script id])
              (io/file (realm-dir root realm) "script" (str (file-name (:name meta)) ".script.json")))
        raw (or (read-json f) {})
        old (or (some (fn [[k v]] (when (= id (:_id v)) [k v])) (:script raw)) [(keyword id) {}])
        old-src (:script (second old))
        js (if (and (string? old-src) (str/starts-with? old-src "file://"))
             old-src
             (when-not (and (string? old-src) (seq (:script raw))) (str "file://" (file-name (:name meta)) ".script.js")))
        entry (assoc (strip (dissoc meta :script)) :script (or js source))]
    (when js (write-text! (io/file (.getParentFile (io/file f)) (subs js 7)) source))
    (write-json! f (assoc-in raw [:script (first old)] entry))
    (assoc-in files [:script id] (io/file f))))

;; ---- IDM config and ESVs -----------------------------------------------------------------

(defn- write-idm-file!
  "A {idm: {id: cfg}} file, keeping extracted scripts extracted."
  [f id cfg]
  (let [raw (or (read-json f) {})
        old (get-in raw [:idm (keyword id)])]
    (write-json! f (assoc-in raw [:idm (keyword id)] (extract-like f old (strip cfg))))))

(defn- write-object-file!
  "A file holding one object at the top level (a managed object, a mapping), or wrapped as
  {idm: {<_id>: object}} when that is how the file has it."
  [f obj]
  (let [old (read-json f)
        meta (:meta old)]
    (if-let [[k inner] (first (:idm old))]
      (write-json! f (assoc-in old [:idm k] (extract-like f inner (strip obj))))
      (write-json! f (cond-> (extract-like f old (strip obj)) meta (assoc :meta meta))))))

(defn- in-old-order
  "Objects of `by-name`, in the order `old` (a list) had them, new ones after."
  [old by-name]
  (let [names (keep #(when (map? %) (:name %)) old)]
    (concat (keep by-name names) (vals (apply dissoc by-name names)))))

(defn- write-listed!
  "managed (objects) or sync (mappings): the objects go to their own files, or inline into the
  list file when that is how the export keeps them; a new object follows the export's layout."
  [root files id k by-name file-key list-key dir suffix]
  (let [list-f (get files list-key)
        raw (some-> list-f read-json)
        listed (get-in raw [:idm (keyword id) k])
        inline? (some map? listed)
        refs? (some string? listed)]
    (if inline?
      (do (write-idm-file! list-f id {:_id id k (vec (in-old-order listed by-name))}) files)
      (reduce (fn [files [n o]]
                (let [known (get-in files [file-key n])
                      f (or known (if refs?
                                    (io/file (.getParentFile (io/file list-f)) (file-name n) (str (file-name n) suffix))
                                    (io/file dir (str (file-name n) suffix))))]
                  (write-object-file! f o)
                  (when (and refs? (not known))
                    (let [raw (read-json list-f)
                          ref (str "file://" (file-name n) "/" (file-name n) suffix)]
                      (write-json! list-f (update-in raw [:idm (keyword id) k] #(vec (distinct (conj (vec %) ref)))))))
                  (assoc-in files [file-key n] (io/file f))))
              files by-name))))

(defn write-config!
  "Write IDM config object `id` as it now is in `t`."
  [root t files id]
  (let [g (global-dir root)]
    (cond
      (str/starts-with? id "endpoint/")
      (let [n (subs id 9)
            f (or (get-in files [:endpoint n]) (io/file g "idm" "endpoint" (str (file-name n) ".idm.json")))]
        (write-idm-file! f id (assoc (get-in t [:idm-endpoints n]) :_id id))
        (assoc-in files [:endpoint n] (io/file f)))

      (= id "managed")
      (write-listed! root files "managed" :objects (:managed-schemas t) :managed :managed-list (io/file g "idm" "managed") ".managed.json")

      (or (= id "sync") (str/starts-with? id "mapping/"))
      (write-listed! root files "sync" :mappings
                     (into {} (for [m (:mappings t) :when (or (= id "sync") (= (:name m) (subs id 8)))] [(:name m) m]))
                     :mapping :mapping-list (io/file g "sync") ".sync.json")

      :else
      (let [f (or (get-in files [:config id]) (io/file g "idm" (str id ".idm.json")))]
        (write-idm-file! f id (get-in t [:idm-config id]))
        (assoc-in files [:config id] (io/file f))))))

(defn write-variable!
  [root t files id]
  (let [f (or (get-in files [:variable id]) (io/file (global-dir root) "variable" (str id ".variable.json")))
        raw (or (read-json f) {})
        old (get-in raw [:variable (keyword id)] {:_id id :description "" :expressionType "string"})
        v (get-in t [:services :esv (str/replace id "-" ".")])]
    (if (nil? v)
      (when (.exists (io/file f)) (io/delete-file f))
      (write-json! f (assoc-in raw [:variable (keyword id)] (strip (dissoc (assoc old :value v) :valueBase64 :loaded)))))
    (assoc-in files [:variable id] (io/file f))))
