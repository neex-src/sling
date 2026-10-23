(ns test
  "The whole suite in a fresh JVM, as CI would run it: clojure -M:test:icf, every namespace under
  test/, exit 1 on any failure. The real-connector test needs `bb hrdb:up` first, else it skips."
  (:require [babashka.fs :as fs]
            [babashka.process :refer [shell]]
            [clojure.string :as str]))

(def namespaces
  (for [f (fs/glob "test" "**_test.clj")]
    (-> (str (fs/relativize "test" f)) (str/replace #"\.clj$" "") (str/replace "/" ".") (str/replace "_" "-"))))

(let [code (str "(require 'clojure.test)"
                "(def nss '[" (str/join " " namespaces) "])"
                "(apply require nss)"
                "(let [r (apply clojure.test/run-tests nss)]"
                "  (shutdown-agents)"
                "  (System/exit (if (zero? (+ (:fail r) (:error r))) 0 1)))")]
  (shell "clojure" "-M:test:icf" "-e" code))
