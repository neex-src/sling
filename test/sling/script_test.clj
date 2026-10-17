(ns sling.script-test
  "The decision scripts on their own: fake state in, outcome and state out. No journey, no server."
  (:require [clojure.edn :as edn]
            [clojure.test :refer [deftest is testing]]
            [sling.script :as script]))

(def services (edn/read-string (slurp "tenant/services.edn")))
(def role-check-src (slurp "tenant/alpha/scripts/network-role-check.js"))
(def otp-check-src (slurp "tenant/alpha/scripts/otp-check.js"))

(defn- run [src in & [svc]] (script/run-script src in (or svc services)))

(deftest network-role-check
  (let [staff {:shared {"username" "alice"} :request {:headers {"x-forwarded-for" ["10.0.4.7"]}}}]
    (testing "staff on the corporate network step up"
      (let [r (run role-check-src staff)]
        (is (= "staff" (:outcome r)))
        (is (= {"tier" "staff"} (:shared r)))
        (is (= {"tier" "staff"} (get-in r [:action :sessionProps])))
        (is (= "risk score for alice: 12" (-> r :logs first :message)))))
    (testing "staff elsewhere are denied, with the message the user would see"
      (let [r (run role-check-src (assoc-in staff [:request :headers "x-forwarded-for"] ["8.8.8.8"]))]
        (is (= "denied" (:outcome r)))
        (is (= "staff must sign in from the corporate network" (get-in r [:action :errorMessage])))))
    (testing "the ESV is a fake like any other: change it, change the answer"
      (is (= "denied" (:outcome (run role-check-src staff (assoc-in services [:esv "esv.corp.network.prefix"] "192.168."))))))
    (testing "customers pass whatever the network"
      (is (= "customer" (:outcome (run role-check-src {:shared {"username" "bob"}})))))
    (testing "a risky user is denied before the role is considered"
      (is (= "denied" (:outcome (run role-check-src (assoc-in staff [:shared "username"] "mallory"))))))))

(deftest otp-check
  (testing "first visit asks for a code and has no outcome"
    (let [r (run otp-check-src {})]
      (is (nil? (:outcome r)))
      (is (= [{:type "TextInputCallback" :args {:prompt "One-time code" :default ""}}] (:callbacks r)))))
  (testing "the answer decides"
    (is (= "true" (:outcome (run otp-check-src {:callbacks [{:type "TextInputCallback" :value "123456"}]}))))
    (is (= "false" (:outcome (run otp-check-src {:callbacks [{:type "TextInputCallback" :value "000000"}]}))))))

(deftest fakes-are-loud
  (testing "an HTTP call nobody faked answers 599 and the script can see it"
    (let [r (run "var r = httpClient.send('https://nobody.test/x').get(); nodeState.putShared('s', r.status); action.goTo('true')" {})]
      (is (= {"s" 599} (:shared r)))))
  (testing "openidm reads the fake managed users"
    (let [r (run "nodeState.putShared('n', openidm.read('managed/user/alice').givenName); action.goTo('true')" {})]
      (is (= {"n" "Alice"} (:shared r)))))
  (testing "a broken script is an error value, not an exception"
    (let [r (run "this is not javascript" {})]
      (is (nil? (:outcome r)))
      (is (re-find #"script error" (:error r))))))
