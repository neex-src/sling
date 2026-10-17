(ns sling.store
  "The git-held tenant: plain files, one per journey, node config and script, so a diff is a review.

    <dir>/services.edn                 the fakes (see sling.script)
    <dir>/<realm>/journeys/<name>.json tree: entryNodeId + nodes with connections
    <dir>/<realm>/nodes/<uuid>.json    node config; \"_type\" holds {_id version}
    <dir>/<realm>/scripts/<name>.js    the script source, as plain text
    <dir>/<realm>/scripts/<name>.json  its metadata, including the _id the nodes point at

  Files are written with sorted keys so repeated exports never produce noise."
  (:require [cheshire.core :as json]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str])
  (:import (java.util Base64)))

(defn- sorted [x]
  (cond (map? x) (into (sorted-map) (map (fn [[k v]] [(name k) (sorted v)]) x))
        (sequential? x) (mapv sorted x)
        :else x))

(defn write-json! [f data]
  (io/make-parents f)
  (spit f (str (json/generate-string (sorted data) {:pretty {:indentation "  " :indent-arrays? true
                                                             :object-field-value-separator ": "}})
               "\n")))

(defn- read-json [f] (json/parse-string (slurp f) true))

(defn- files [dir ext]
  (->> (.listFiles (io/file dir))
       (filter #(and (.isFile %) (str/ends-with? (.getName %) ext)))
       (sort-by #(.getName %))))

(defn- base-name [f] (str/replace (.getName f) #"\.[^.]+$" ""))

(defn load-tenant
  "Read <dir> into {:dir :realm :services :trees {name tree} :nodes {id cfg} :scripts {id {:meta :source}}}."
  [dir realm]
  (let [r (io/file dir realm)
        sub #(io/file r %)
        services (let [f (io/file dir "services.edn")] (if (.exists f) (edn/read-string (slurp f)) {}))]
    {:dir dir :realm realm :services services
     :trees (into {} (for [f (files (sub "journeys") ".json")] [(base-name f) (read-json f)]))
     :nodes (into {} (for [f (files (sub "nodes") ".json")] [(base-name f) (read-json f)]))
     :scripts (into {} (for [f (files (sub "scripts") ".json")
                             :let [m (read-json f)
                                   js (io/file (sub "scripts") (str (base-name f) ".js"))]]
                         [(:_id m) {:meta m :source (if (.exists js) (slurp js) "")}]))}))

(defn put-tree! [dir realm name tree]
  (write-json! (io/file dir realm "journeys" (str name ".json")) (assoc tree :_id name)))

(defn put-node! [dir realm type version id cfg]
  (write-json! (io/file dir realm "nodes" (str id ".json"))
               (assoc cfg :_type {:_id type :version version} :_id id)))

(defn put-script!
  "`body` is the REST representation: :script is base64. Written as <name>.js + <name>.json."
  [dir realm id {:keys [name script] :as body}]
  (let [src (String. (.decode (Base64/getDecoder) ^String script) "UTF-8")
        sd (io/file dir realm "scripts")]
    (io/make-parents (io/file sd "x"))
    (spit (io/file sd (str name ".js")) src)
    (write-json! (io/file sd (str name ".json")) (-> body (dissoc :script) (assoc :_id id)))))

(defn script-rest
  "REST representation of a stored script (base64 source), as GET /scripts/<id> answers."
  [{:keys [meta source]}]
  (assoc meta :script (.encodeToString (Base64/getEncoder) (.getBytes ^String source "UTF-8"))))

(defn normalize!
  "Rewrite every file of the tenant in the canonical form (sorted keys, same indentation), so an
  export from a real tenant diffs cleanly against what is in git."
  [dir realm]
  (let [t (load-tenant dir realm)]
    (doseq [[n tree] (:trees t)] (put-tree! dir realm n tree))
    (doseq [[id cfg] (:nodes t)]
      (put-node! dir realm (get-in cfg [:_type :_id]) (get-in cfg [:_type :version]) id (dissoc cfg :_type :_id)))
    (doseq [[id s] (:scripts t)] (put-script! dir realm id (script-rest s)))))
