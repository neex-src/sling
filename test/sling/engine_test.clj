(ns sling.engine-test
  "Whole journeys against the demo tenant, driven the way a client drives /authenticate."
  (:require [clojure.test :refer [deftest is testing]]
            [sling.engine :as engine]
            [sling.store :as store]))

(def tenant (store/load-tenant "tenant" "alpha"))

(defn drive
  "Start `journey`, then answer each round of callbacks from `values` until the journey ends."
  [t journey request values]
  (loop [res (engine/start t journey request) vs values]
    (if (= :callbacks (:status res))
      (let [n (count (filter :input (:callbacks res)))]
        (recur (engine/resume t (:session res) (engine/answer (:callbacks res) (take n vs)))
               (drop n vs)))
      res)))

(defn- nodes [res] (mapv :node (get-in res [:session :trace])))
(def corp {:headers {"x-forwarded-for" ["10.0.4.7"]}})

(deftest staff-path
  (let [r (drive tenant "Login" corp ["alice" "alice-pw" "123456"])]
    (is (= :success (:status r)))
    (is (= {"tier" "staff"} (get-in r [:session :props])))
    (is (= ["Username Collector" "Password Collector" "Data Store Decision" "Network and role check" "One-time code"]
           (nodes r)))
    (testing "the inner journey ran under its own name"
      (is (= "StaffMfa" (get-in r [:session :trace 4 :journey]))))
    (testing "the password never reaches shared state"
      (is (not (contains? (get-in r [:session :shared]) "password"))))))

(deftest staff-path-refusals
  (testing "wrong code"
    (is (= :failure (:status (drive tenant "Login" corp ["alice" "alice-pw" "000000"])))))
  (testing "right code, wrong network: refused before the code is even asked for"
    (let [r (drive tenant "Login" {:headers {"x-forwarded-for" ["8.8.8.8"]}} ["alice" "alice-pw"])]
      (is (= :failure (:status r)))
      (is (= "staff must sign in from the corporate network" (get-in r [:session :error-message]))))))

(deftest customer-and-failures
  (let [r (drive tenant "Login" {} ["bob" "bob-pw"])]
    (is (= :success (:status r)))
    (is (= {"tier" "customer"} (get-in r [:session :props]))))
  (testing "wrong password stops at the data store"
    (let [r (drive tenant "Login" {} ["bob" "nope"])]
      (is (= :failure (:status r)))
      (is (= "Data Store Decision" (last (nodes r))))))
  (testing "a high risk score denies even a valid customer"
    (is (= :failure (:status (drive tenant "Login" {} ["mallory" "mallory-pw"]))))))

(deftest honest-failures
  (testing "unknown journey"
    (is (= "Tree does not exist" (:reason (engine/start tenant "Nope" {})))))
  (testing "a node type that is not implemented fails loudly"
    (let [t (assoc-in tenant [:trees "Login" :nodes (keyword (get-in tenant [:trees "Login" :entryNodeId])) :nodeType] "SocialProviderHandlerNode")
          r (engine/start t "Login" {})]
      (is (= :failure (:status r)))
      (is (re-find #"SocialProviderHandlerNode is not implemented" (:reason r))))))
