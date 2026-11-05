(ns image
  "bb image: the uberjar (build.clj) on a JRE image with podman -> localhost/sling:<VERSION>.
  The build context is target/image (Containerfile + sling.jar). The image serves a Frodo export mounted at /tenant."
  (:require [babashka.fs :as fs]
            [babashka.process :refer [shell]]
            [clojure.string :as str]))

(let [version (str/trim (slurp "VERSION"))
      tag (str "localhost/sling:" version)]
  (shell "clojure" "-T:build" "uber")
  (fs/delete-tree "target/image")
  (fs/create-dirs "target/image")
  (fs/copy "image/Containerfile" "target/image/Containerfile")
  (fs/copy "target/sling.jar" "target/image/sling.jar")
  (shell "podman" "build" "-t" tag "target/image")
  (println "built" tag))
