(ns sling.frodojson-test
  "The writer against files Frodo itself wrote: reading one and writing it again gives the same bytes."
  (:require [cheshire.core :as json]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [sling.frodojson :as fj]))

(deftest frodo-files-round-trip-byte-for-byte
  (let [files (->> (file-seq (io/file "test/fixtures/frodo-written"))
                   (filter #(str/ends-with? (.getName %) ".json")))]
    (is (<= 8 (count files)))
    (doseq [f files]
      (testing (str f)
        (is (= (slurp f) (fj/file-text (json/parse-string (slurp f) true))))))))

(deftest javascript-rules
  (testing "index-like keys first, numerically; the rest by code unit"
    (is (= "{\n  \"2\": 0,\n  \"10\": 0,\n  \"B\": 0,\n  \"a\": 0\n}" (fj/stringify {"a" 0 "B" 0 "10" 0 "2" 0}))))
  (testing "escapes as JSON.stringify: control characters only, lower-case hex"
    (is (= "\"é \\u001b \\n / <\"" (fj/stringify "é \u001b \n / <"))))
  (testing "empty containers and integral numbers"
    (is (= "{\n  \"a\": [],\n  \"b\": {},\n  \"c\": 105.015625,\n  \"d\": 3\n}" (fj/stringify {:a [] :b {} :c 105.015625 :d 3.0})))))
