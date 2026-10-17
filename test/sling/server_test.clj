(ns sling.server-test
  "Over HTTP, the way a real client and the deploy script talk to it."
  (:require [cheshire.core :as json]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [sling.server :as server])
  (:import (java.net URI)
           (java.net.http HttpClient HttpRequest HttpRequest$BodyPublishers HttpResponse$BodyHandlers)
           (java.nio.file Files Path StandardCopyOption)))

(defn- copy-tenant!
  "Copy tenant/ into a fresh folder under .scratch/ so tests may write to it."
  []
  (let [dst (io/file ".scratch" (str "tenant-" (System/nanoTime)))
        src (.toPath (io/file "tenant"))]
    (doseq [^Path p (iterator-seq (.iterator (Files/walk src (make-array java.nio.file.FileVisitOption 0))))
            :let [target (.resolve (.toPath dst) (.relativize src p))]]
      (if (Files/isDirectory p (make-array java.nio.file.LinkOption 0))
        (Files/createDirectories target (make-array java.nio.file.attribute.FileAttribute 0))
        (Files/copy p target (into-array StandardCopyOption [StandardCopyOption/REPLACE_EXISTING]))))
    (str dst)))

(def ^:private http (HttpClient/newHttpClient))

(defn- call [srv method path & {:keys [body headers]}]
  (let [b (cond-> (HttpRequest/newBuilder (URI. (str "http://127.0.0.1:" (:port srv) path)))
            true (.header "Content-Type" "application/json"))
        b (reduce (fn [b [k v]] (.header b k v)) b headers)
        req (-> b (.method method (if body (HttpRequest$BodyPublishers/ofString (json/generate-string body))
                                      (HttpRequest$BodyPublishers/noBody)))
                .build)
        r (.send http req (HttpResponse$BodyHandlers/ofString))]
    {:status (.statusCode r) :body (json/parse-string (.body r) true)}))

(def ^:private auth "/am/json/realms/root/realms/alpha/authenticate")

(defn- login [srv headers & values]
  (loop [r (call srv "POST" auth :headers headers) vs values]
    (if-let [cbs (get-in r [:body :callbacks])]
      (let [n (count (filter :input cbs))]
        (recur (call srv "POST" auth :headers headers
                     :body {:authId (get-in r [:body :authId])
                            :callbacks (sling.engine/answer cbs (take n vs))})
               (drop n vs)))
      r)))

(deftest authenticate-loop
  (let [srv (server/start! {:port 0 :dir "tenant"})]
    (try
      (testing "the callback loop ends in a session token"
        (let [r (login srv {"X-Forwarded-For" "10.0.4.7"} "alice" "alice-pw" "123456")]
          (is (= 200 (:status r)))
          (is (str/starts-with? (get-in r [:body :tokenId]) "AQIC"))
          (is (= "/alpha" (get-in r [:body :realm])))))
      (testing "first call returns a NameCallback with the real wire shape"
        (let [b (:body (call srv "POST" auth))]
          (is (= "NameCallback" (get-in b [:callbacks 0 :type])))
          (is (= "IDToken1" (get-in b [:callbacks 0 :input 0 :name])))))
      (testing "a refusal is a 401, and debug mode says why"
        (let [r (login srv {"X-Sling-Debug" "true"} "bob" "wrong")]
          (is (= 401 (:status r)))
          (is (= "Login failure" (get-in r [:body :message])))
          (is (re-find #"Data Store Decision" (get-in r [:body :_sling :reason])))))
      (testing "the journey can be chosen by name"
        (let [r (call srv "POST" (str auth "?authIndexType=service&authIndexValue=StaffMfa"))]
          (is (= "TextInputCallback" (get-in r [:body :callbacks 0 :type])))))
      (finally (server/stop! srv)))))

(deftest deploy-by-put
  (let [dir (copy-tenant!)
        srv (server/start! {:port 0 :dir dir})
        scripts "/am/json/realms/root/realms/alpha/scripts/6088b6ba-a712-46ac-b3cd-c50612f0a24c"
        token {"Authorization" "Bearer local-dev"}]
    (try
      (testing "management calls need a token"
        (is (= 401 (:status (call srv "GET" scripts)))))
      (testing "putting back what you read changes no file: exports stay diff-free"
        (let [before (slurp (io/file dir "alpha/scripts/otp-check.json"))
              got (:body (call srv "GET" scripts :headers token))]
          (is (= 200 (:status (call srv "PUT" scripts :headers token :body got))))
          (is (= before (slurp (io/file dir "alpha/scripts/otp-check.json"))))))
      (testing "a PUT changes behaviour at once and lands in the files"
        (let [got (:body (call srv "GET" scripts :headers token))
              new-src "action.goTo('true');"
              put (assoc got :script (.encodeToString (java.util.Base64/getEncoder) (.getBytes new-src "UTF-8")))]
          (is (= 200 (:status (call srv "PUT" scripts :headers token :body put))))
          (is (= new-src (slurp (io/file dir "alpha/scripts/otp-check.js"))))
          (is (= 200 (:status (login srv {"X-Forwarded-For" "10.0.4.7"} "alice" "alice-pw"))))))
      (testing "journeys read back as written"
        (let [r (call srv "GET" "/am/json/realms/root/realms/alpha/realm-config/authentication/authenticationtrees/trees/Login"
                      :headers token)]
          (is (= "Login" (get-in r [:body :_id])))))
      (finally (server/stop! srv)))))
