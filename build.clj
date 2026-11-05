(ns build
  "The uberjar of the fake tenant with the :icf deps (the Groovy connector), for `bb image`:
  clojure -T:build uber -> target/sling.jar, started as `java -cp sling.jar clojure.main -m sling.server`
  (sources are compiled at start; nothing is AOT-compiled, so GraalJS and the connector classes load as in `bb serve`)."
  (:require [clojure.tools.build.api :as b]))

(def class-dir "target/classes")
(def jar-file "target/sling.jar")

(defn uber [_]
  (b/delete {:path "target"})
  (let [basis (b/create-basis {:aliases [:icf]})]
    (b/copy-dir {:src-dirs ["src" "resources"] :target-dir class-dir})
    (b/uber {:class-dir class-dir :uber-file jar-file :basis basis})
    (println "built" jar-file)))
