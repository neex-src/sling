(ns deploy
  "Push the git-held tenant to a tenant API: scripts first, then node configs, then journeys
  (inner-only journeys before the ones that call them). A resource whose local fields already
  match what the tenant returns is skipped, so a re-run after a merge touches only what changed.
  --dry-run lists what would be sent."
  (:require [babashka.cli :as cli]
            [babashka.fs :as fs]
            [babashka.http-client :as http]
            [cheshire.core :as json]
            [clojure.string :as str])
  (:import (java.util Base64)))

(def opts (cli/parse-opts *command-line-args*
                          {:coerce {:dry-run :boolean} :alias {:b :base :t :token}
                           :require [:base :token]}))
(def dir (or (:dir opts) "tenant"))
(def realm (or (:realm opts) "alpha"))
(def api (str (str/replace (:base opts) #"/+$" "") "/am/json/realms/root/realms/" realm))
(def headers {"Authorization" (str "Bearer " (:token opts)) "Content-Type" "application/json"
              "Accept-API-Version" "protocol=2.1,resource=3.0"})

(defn read-json [f] (json/parse-string (slurp (str f)) true))
(defn files [sub ext] (sort (fs/glob (fs/path dir realm sub) (str "*" ext))))
(defn subset? [local remote] (every? (fn [[k v]] (= v (get remote k))) local))

(defn put! [label url body]
  (let [got (http/get url {:headers headers :throw false})
        same (and (= 200 (:status got)) (subset? body (json/parse-string (:body got) true)))]
    (cond same (println "  unchanged" label)
          (:dry-run opts) (println "  would PUT" label)
          :else (let [r (http/put url {:headers headers :body (json/generate-string body) :throw false})]
                  (println (if (= 200 (:status r)) "  PUT      " (str "  FAILED " (:status r) " ")) label)
                  (when-not (= 200 (:status r)) (println (:body r)) (System/exit 1))))))

(println "deploying" dir "to" api (if (:dry-run opts) "(dry run)" ""))
(doseq [f (files "scripts" ".json")
        :let [m (read-json f)
              src (slurp (str (fs/strip-ext f) ".js"))]]
  (put! (str "script " (:name m)) (str api "/scripts/" (:_id m))
        (assoc m :script (.encodeToString (Base64/getEncoder) (.getBytes ^String src "UTF-8")))))
(doseq [f (files "nodes" ".json")
        :let [c (read-json f)]]
  (put! (str "node " (get-in c [:_type :_id]) " " (:_id c))
        (str api "/realm-config/authentication/authenticationtrees/nodes/"
             (get-in c [:_type :_id]) "/" (get-in c [:_type :version]) "/" (:_id c))
        c))
(doseq [t (sort-by (comp not :innerTreeOnly) (map read-json (files "journeys" ".json")))]
  (put! (str "journey " (:_id t)) (str api "/realm-config/authentication/authenticationtrees/trees/" (:_id t)) t))
