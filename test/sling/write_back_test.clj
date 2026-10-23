(ns sling.write-back-test
  "serve --write on a Frodo export: what the API changes lands in the export's own files, in
  Frodo's format, and nothing else moves."
  (:require [cheshire.core :as json]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [sling.engine :as engine]
            [sling.frodo :as frodo]
            [sling.server :as server]
            [sling.web :as web])
  (:import (java.nio.file Files LinkOption Path StandardCopyOption)
           (java.nio.file.attribute FileAttribute)
           (java.util Base64)))

(defn- copy-dir! [src]
  (let [dst (io/file ".scratch" (str "export-" (System/nanoTime)))
        s (.toPath (io/file src))]
    (doseq [^Path p (iterator-seq (.iterator (Files/walk s (make-array java.nio.file.FileVisitOption 0))))
            :let [t (.resolve (.toPath dst) (.relativize s p))]]
      (if (Files/isDirectory p (make-array LinkOption 0))
        (Files/createDirectories t (make-array FileAttribute 0))
        (Files/copy p t (into-array StandardCopyOption [StandardCopyOption/REPLACE_EXISTING]))))
    (str dst)))

(defn- snapshot [dir]
  (into {} (for [f (file-seq (io/file dir)) :when (.isFile f)]
             [(str (.relativize (.toPath (io/file dir)) (.toPath f))) (slurp f)])))

(defn- changed [before after]
  (set (for [k (into (set (keys before)) (keys after)) :when (not= (before k) (after k))] k)))

(def ^:dynamic *srv* nil)

(defn- call [method path & {:keys [body query]}]
  (let [r (server/handle *srv* {:method method :path path :query (update-vals (or query {}) vector)
                                :headers {"authorization" ["Bearer local-dev"]}
                                :body (if body (json/generate-string body) "")})]
    (update r :body #(if (string? %) (json/parse-string % true) %))))

(defmacro with-server [dir & body]
  `(let [s# (server/start! {:port 0 :frodo ~dir :services "test/fixtures/frodo-services.edn" :write true})]
     (try (binding [*srv* s#] ~@body) (finally (server/stop! s#)))))

(def am "/am/json/realms/root/realms/alpha")
(def trees (str am "/realm-config/authentication/authenticationtrees"))

(deftest putting-back-what-was-read-changes-nothing
  (let [dir (copy-dir! "test/fixtures/frodo-export")
        before (snapshot dir)]
    (with-server dir
      (doseq [[n _] (:trees @(:tenant *srv*))]
        (let [tree (:body (call "GET" (str trees "/trees/" n)))]
          (doseq [[id node] (:nodes tree)
                  :let [cfg (:body (call "GET" (str trees "/nodes/" (:nodeType node) "/" (name id))))]]
            (doseq [c (:nodes cfg)]
              (call "PUT" (str trees "/nodes/" (:nodeType c) "/1.0/" (:_id c))
                    :body (:body (call "GET" (str trees "/nodes/" (:nodeType c) "/" (:_id c))))))
            (call "PUT" (str trees "/nodes/" (:nodeType node) "/1.0/" (name id)) :body cfg))
          (call "PUT" (str trees "/trees/" n) :body tree)))
      (doseq [s (get-in (call "GET" (str am "/scripts")) [:body :result])]
        (call "PUT" (str am "/scripts/" (:_id s)) :body s))
      (doseq [id ["endpoint/orderSummary" "managed" "sync" "provisioner.openicf/HRDB"]]
        (call "PUT" (str "/openidm/config/" id) :body (:body (call "GET" (str "/openidm/config/" id))))))
    (is (= #{} (changed before (snapshot dir))))))

(deftest changes-land-in-their-files
  (let [dir (copy-dir! "test/fixtures/frodo-export")
        before (snapshot dir)
        login "realm/root-alpha/journey/PlatformLogin.journey.json"]
    (with-server dir
      (testing "a script: only its .js"
        (let [s (:body (call "GET" (str am "/scripts/5d8f1c2e-3b4a-4c5d-9e6f-7a8b9c0d1e01")))]
          (call "PUT" (str am "/scripts/" (:_id s))
                :body (assoc s :script (.encodeToString (Base64/getEncoder) (.getBytes "action.goTo(\"guest\");\n" "UTF-8"))))
          (is (= #{"realm/root-alpha/script/Member-check.script.js"} (changed before (snapshot dir))))
          (is (= "action.goTo(\"guest\");\n" (slurp (io/file dir "realm/root-alpha/script/Member-check.script.js"))))))
      (testing "a node setting: its journey file, one line"
        (let [b (snapshot dir)
              path (str trees "/nodes/RetryLimitDecisionNode/2c6d9b63-7a6e-4b4f-8b62-1e2d3f4a5b03")]
          (call "PUT" (str trees "/nodes/RetryLimitDecisionNode/1.0/2c6d9b63-7a6e-4b4f-8b62-1e2d3f4a5b03")
                :body (assoc (:body (call "GET" path)) :retryLimit 5))
          (is (= #{login} (changed b (snapshot dir))))
          (is (= [["          \"retryLimit\": 3" "          \"retryLimit\": 5"]]
                 (remove (fn [[x y]] (= x y)) (map vector (str/split-lines (b login)) (str/split-lines (slurp (io/file dir login)))))))))
      (testing "a new journey, the way Frodo imports one: nodes first, then the tree"
        (let [b (snapshot dir)
              n1 "9a000000-0000-4000-8000-000000000001"]
          (call "PUT" (str trees "/nodes/ScriptedDecisionNode/1.0/" n1)
                :body {:_id n1 :_type {:_id "ScriptedDecisionNode" :collection true :name "Scripted Decision"}
                       :script "5d8f1c2e-3b4a-4c5d-9e6f-7a8b9c0d1e01" :outcomes ["member" "guest"] :inputs ["*"] :outputs ["*"]})
          (is (= #{} (changed b (snapshot dir))) "a node alone is not written until a journey uses it")
          (call "PUT" (str trees "/trees/Quick")
                :body {:_id "Quick" :enabled true :entryNodeId n1 :identityResource "managed/alpha_user"
                       :nodes {(keyword n1) {:nodeType "ScriptedDecisionNode" :displayName "Guest?" :x 0 :y 0
                                             :connections {:guest "70e691a5-1e33-4ac3-a356-e7b6d60d92e0"
                                                           :member "e301438c-0bd0-429c-ab0c-66126501069a"}}}})
          (is (= #{"realm/root-alpha/journey/Quick.journey.json"} (changed b (snapshot dir))))
          (let [t (frodo/load-tenant dir "alpha")]
            (is (= :success (:status (engine/start t "Quick" {})))) "the written export loads and runs")))
      (testing "IDM config: an endpoint, managed object scripts, a mapping"
        (let [b (snapshot dir)
              ep (:body (call "GET" "/openidm/config/endpoint/orderSummary"))
              managed (:body (call "GET" "/openidm/config/managed"))]
          (call "PUT" "/openidm/config/endpoint/orderSummary" :body (assoc ep :source "({ ok: true });"))
          (call "PUT" "/openidm/config/managed"
                :body (update managed :objects (fn [os] (mapv #(assoc-in % [:onCreate :source] "object.sn = 'x';") os))))
          (is (= #{"global/idm/endpoint/orderSummary.idm.json" "global/idm/managed/alpha_user.managed.json"} (changed b (snapshot dir))))
          (is (= "({ ok: true });" (get-in (json/parse-string (slurp (io/file dir "global/idm/endpoint/orderSummary.idm.json")) true)
                                           [:idm :endpoint/orderSummary :source])))))
      (testing "an ESV"
        (let [b (snapshot dir)]
          (call "PUT" "/environment/variables/esv-member-domain" :body {:valueBase64 (.encodeToString (Base64/getEncoder) (.getBytes "x.test"))})
          (is (= #{"global/variable/esv-member-domain.variable.json"} (changed b (snapshot dir))))
          (is (= "x.test" (get-in (json/parse-string (slurp (io/file dir "global/variable/esv-member-domain.variable.json")) true)
                                  [:variable :esv-member-domain :value]))))))))

(deftest extracted-scripts-stay-extracted
  (let [dir (copy-dir! "test/fixtures/frodo-written/idm")
        before (snapshot dir)]
    (with-server dir
      (let [ep (:body (call "GET" "/openidm/config/endpoint/orderSummary"))]
        (call "PUT" "/openidm/config/endpoint/orderSummary" :body (assoc ep :source "({ ok: true });"))))
    (is (= #{"endpoint/orderSummary/orderSummary.js"} (changed before (snapshot dir))))
    (is (= "({ ok: true });" (slurp (io/file dir "endpoint/orderSummary/orderSummary.js"))))))

(deftest without-write-the-export-is-left-alone
  (let [dir (copy-dir! "test/fixtures/frodo-export")
        before (snapshot dir)
        s (server/start! {:port 0 :frodo dir :services "test/fixtures/frodo-services.edn"})]
    (try
      (binding [*srv* s]
        (call "PUT" "/openidm/config/endpoint/orderSummary" :body {:type "text/javascript" :source "({});"}))
      (finally (server/stop! s)))
    (is (= #{} (changed before (snapshot dir))))))
