(ns sling.acme-gaps-test
  "What the Acme tenant (acme-identity) needed that was missing: zero-page login, the implicit grant, the outbox by address,
  an ESV that keeps its description. Each is a thing the public docs describe; none is Acme-specific."
  (:require [cheshire.core :as json]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [sling.engine :as engine]
            [sling.server :as server]
            [sling.web :as web]))

(def export "test/fixtures/frodo-export")
(def realm "/am/json/realms/root/realms/alpha")
(def oauth "/am/oauth2/realms/root/realms/alpha")

(defn- call [srv method path & {:keys [query headers body]}]
  (let [r (server/handle srv {:method method :path path :query (update-vals (or query {}) vector)
                              :headers (update-vals (update-keys (or headers {}) str/lower-case) vector)
                              :body (if body (json/generate-string body) "")})]
    (cond-> r (string? (:body r)) (update :body #(if (str/blank? %) % (try (json/parse-string % true) (catch Exception _ %)))))))

(defn- scratch-dir [prefix] (doto (io/file ".scratch" (str prefix "-" (System/nanoTime))) .mkdirs))

;; ---- zero-page login ---------------------------------------------------------------------------

(defn- write-json! [f x] (io/make-parents f) (spit f (json/generate-string x)))

(defn- zero-page-export
  "A Frodo-shaped export of one journey: Zero Page Login Collector -> (credentials) Identity Store Decision / (none) Page Node -> Identity Store Decision."
  []
  (let [d (scratch-dir "zp-export")
        zp "00000000-0000-4000-8000-000000000001" pg "00000000-0000-4000-8000-000000000002" ids "00000000-0000-4000-8000-000000000003"
        un "00000000-0000-4000-8000-000000000004" pw "00000000-0000-4000-8000-000000000005"
        ok "70e691a5-1e33-4ac3-a356-e7b6d60d92e0" no "e301438c-0bd0-429c-ab0c-66126501069a"
        node (fn [id t] {:_id id :_type {:_id t :collection true :name t}})]
    (write-json! (io/file d "realm/root-alpha/journey/ZeroPage.journey.json")
                 {:trees {:ZeroPage
                          {:innerNodes {(keyword un) (node un "ValidatedUsernameNode") (keyword pw) (node pw "ValidatedPasswordNode")}
                           :nodes {(keyword zp) (node zp "ZeroPageLoginNode")
                                   (keyword pg) (assoc (node pg "PageNode") :nodes [{:_id un :nodeType "ValidatedUsernameNode"} {:_id pw :nodeType "ValidatedPasswordNode"}])
                                   (keyword ids) (node ids "IdentityStoreDecisionNode")}
                           :scripts {}
                           :tree {:_id "ZeroPage" :enabled true :entryNodeId zp :identityResource "managed/alpha_user"
                                  :nodes {(keyword zp) {:nodeType "ZeroPageLoginNode" :connections {:hasCredentials ids :noCredentials pg}}
                                          (keyword pg) {:nodeType "PageNode" :connections {:outcome ids}}
                                          (keyword ids) {:nodeType "IdentityStoreDecisionNode"
                                                         :connections {:TRUE ok :FALSE no :LOCKED no :CANCELLED no :EXPIRED no}}}}}}})
    (str d)))

(defn- zero-page-server []
  (let [svc (io/file (scratch-dir "zp-svc") "services.edn")]
    (spit svc (pr-str {:default-journey "ZeroPage"
                       :idm {"alpha_user" [{:_id "11111111-0000-4000-8000-000000000001" :userName "zed" :password "Zed-pw-1" :accountStatus "active" :mail "zed@example.test"}]}}))
    (server/start! {:port 0 :frodo (zero-page-export) :services (str svc)})))

(deftest zero-page-login
  (let [srv (zero-page-server)]
    (try
      (testing "the tenant says zero page login is on"
        (is (true? (get-in (call srv "GET" "/am/json/serverinfo/*") [:body :zeroPageLogin :enabled]))))
      (testing "the credentials in the headers, an empty body: one request, a session"
        (let [r (call srv "POST" (str realm "/authenticate") :headers {"X-OpenAM-Username" "zed" "X-OpenAM-Password" "Zed-pw-1"})]
          (is (= 200 (:status r)))
          (is (str/starts-with? (get-in r [:body :tokenId]) "AQIC"))))
      (testing "wrong password in the headers: the journey goes down its FALSE path, failure"
        (is (= 401 (:status (call srv "POST" (str realm "/authenticate") :headers {"X-OpenAM-Username" "zed" "X-OpenAM-Password" "no"})))))
      (testing "no headers: the page node asks for both"
        (is (= ["NameCallback" "PasswordCallback"]
               (map :type (get-in (call srv "POST" (str realm "/authenticate")) [:body :callbacks])))))
      (testing "only one of the two headers is no credentials"
        (is (= 2 (count (get-in (call srv "POST" (str realm "/authenticate") :headers {"X-OpenAM-Username" "zed"}) [:body :callbacks])))))
      (finally (server/stop! srv)))))

(deftest zero-page-node-rules
  (let [run (fn [config headers] (engine/run-node {:type "ZeroPageLoginNode" :config config :session {:request {:headers headers}}}))]
    (is (= "hasCredentials" (:outcome (run {} {"x-openam-username" ["a"] "x-openam-password" ["b"]}))))
    (is (= {"username" "a"} (:shared (run {} {"x-openam-username" ["a"] "x-openam-password" ["b"]}))))
    (is (= {"password" "b"} (:transient (run {} {"x-openam-username" ["a"] "x-openam-password" ["b"]}))))
    (testing "header names are configurable"
      (is (= "hasCredentials" (:outcome (run {:usernameHeader "X-U" :passwordHeader "X-P"} {"x-u" ["a"] "x-p" ["b"]}))))
      (is (= "noCredentials" (:outcome (run {:usernameHeader "X-U" :passwordHeader "X-P"} {"x-openam-username" ["a"] "x-openam-password" ["b"]})))))
    (testing "Allow without referer off: the Referer must be on the list"
      (let [h {"x-openam-username" ["a"] "x-openam-password" ["b"]}
            cfg {:allowWithoutReferer false :referrerWhiteList ["https://app.example/"]}]
        (is (= "noCredentials" (:outcome (run cfg h))))
        (is (= "noCredentials" (:outcome (run cfg (assoc h "referer" ["https://evil.example/"])))))
        (is (= "hasCredentials" (:outcome (run cfg (assoc h "referer" ["https://app.example/"])))))))
    (testing "two values for one header is an error, as the node reference says"
      (is (re-find #"Expecting only one header value" (:error (run {} {"x-openam-username" ["a" "b"] "x-openam-password" ["p"]})))))))

;; ---- implicit grant ----------------------------------------------------------------------------

(deftest implicit-grant
  (let [svc (io/file (scratch-dir "implicit-svc") "services.edn")
        _ (spit svc (pr-str {:default-journey "PlatformLogin"
                             :clients {"spa" {:grantTypes ["implicit"] :clientType "Public" :scopes ["openid" "profile"] :defaultScopes ["openid"]
                                              :redirectUris ["https://app.example/cb"]}
                                       "plain" {:grantTypes ["authorization_code"] :clientType "Public" :scopes ["openid"] :redirectUris ["https://app.example/cb"]}}
                             :idm {"alpha_user" [{:_id "22222222-0000-4000-8000-000000000001" :userName "ivy" :password "Ivy-pw-1" :accountStatus "active"
                                                  :mail "ivy@example.test" :givenName "Ivy"}]}}))
        srv (server/start! {:port 0 :frodo export :services (str svc)})
        iss (str (get-in srv [:opts :public-url]) oauth)
        q (fn [client] {"client_id" client "redirect_uri" "https://app.example/cb" "response_type" "token" "scope" "openid profile" "state" "st-1"})
        sso (let [r1 (call srv "POST" (str realm "/authenticate"))
                  r2 (call srv "POST" (str realm "/authenticate") :body {:authId (get-in r1 [:body :authId]) :callbacks (engine/answer (get-in r1 [:body :callbacks]) ["ivy" "Ivy-pw-1"])})]
              (first (str/split (first (get-in r2 [:headers "Set-Cookie"])) #";")))]
    (try
      (testing "a session and a client with the implicit grant: 302, the token in the fragment"
        (let [r (call srv "GET" (str oauth "/authorize") :query (q "spa") :headers {"Cookie" sso})
              loc (get-in r [:headers "Location"])
              [base frag] (str/split loc #"#" 2)
              params (into {} (for [[k [v]] (web/decode-form frag)] [k v]))
              claims (json/parse-string (String. (.decode (java.util.Base64/getUrlDecoder) ^String (second (str/split (params "access_token") #"\."))) "UTF-8") true)]
          (is (= 302 (:status r)))
          (is (= "https://app.example/cb" base))
          (is (= "Bearer" (params "token_type")))
          (is (= "st-1" (params "state")))
          (is (= iss (params "iss")))
          (is (= "openid profile" (params "scope")))
          (is (= {:sub "22222222-0000-4000-8000-000000000001" :client_id "spa" :iss iss :grant_type "implicit"} (select-keys claims [:sub :client_id :iss :grant_type])))
          (testing "and the fake accepts it"
            (is (= "22222222-0000-4000-8000-000000000001"
                   (get-in (call srv "GET" (str oauth "/userinfo") :headers {"Authorization" (str "Bearer " (params "access_token"))}) [:body :sub]))))))
      (testing "a client without the implicit grant is refused, in the redirect"
        (let [loc (get-in (call srv "GET" (str oauth "/authorize") :query (q "plain") :headers {"Cookie" sso}) [:headers "Location"])]
          (is (str/includes? loc "error=unauthorized_client"))
          (is (not (str/includes? loc "access_token")))))
      (testing "without a session the way to the login page, as for the code flow"
        (is (str/includes? (get-in (call srv "GET" (str oauth "/authorize") :query (q "spa")) [:headers "Location"]) "/am/XUI/")))
      (testing "the code flow is as it was"
        (is (str/includes? (get-in (call srv "GET" (str oauth "/authorize") :query (assoc (q "plain") "response_type" "code" "scope" "openid") :headers {"Cookie" sso}) [:headers "Location"]) "code=")))
      (testing "discovery says what is supported"
        (let [d (:body (call srv "GET" (str oauth "/.well-known/openid-configuration")))]
          (is (some #{"token"} (:response_types_supported d)))
          (is (some #{"implicit"} (:grant_types_supported d)))))
      (finally (server/stop! srv)))))

;; ---- the outbox by address ---------------------------------------------------------------------

(deftest outbox-by-address
  (let [srv (server/start! {:port 0 :frodo export :services "test/fixtures/frodo-services.edn"})
        otp-login! (fn []
                     (let [r1 (call srv "POST" (str realm "/authenticate") :query {"authIndexType" "service" "authIndexValue" "EmailOtp"})
                           r2 (call srv "POST" (str realm "/authenticate") :body {:authId (get-in r1 [:body :authId]) :callbacks (engine/answer (get-in r1 [:body :callbacks]) ["dan" "Dan-pw-123"])})]
                       (is (= ["PasswordCallback"] (map :type (get-in r2 [:body :callbacks]))))))
        outbox (fn [& [query]] (get-in (call srv "GET" "/sling/outbox" :query query) [:body :result]))]
    (try
      (otp-login!) (otp-login!)
      (testing "plain: everything, oldest first, as before"
        (is (= 2 (count (outbox)))))
      (testing "?to= only that address's mail"
        (is (= 2 (count (outbox {"to" "dan@elsewhere.test"}))))
        (is (= [] (outbox {"to" "nobody@elsewhere.test"}))))
      (testing "?order=newest turns it around: $.result[0] is the last mail, with its code"
        (is (= (reverse (outbox)) (outbox {"order" "newest"})))
        (is (re-matches #"\d{6}" (:otp (first (outbox {"to" "dan@elsewhere.test" "order" "newest"}))))))
      (finally (server/stop! srv)))))

;; ---- ESV metadata ------------------------------------------------------------------------------

(deftest esv-keeps-its-description
  (let [srv (server/start! {:port 0 :frodo export :services "test/fixtures/frodo-services.edn"})
        admin {"Authorization" "Bearer local-dev"}]
    (try
      (testing "from the export"
        (let [v (:body (call srv "GET" "/environment/variables/esv-orders-url" :headers admin))]
          (is (= "Base URL of the orders service" (:description v)))
          (is (= "string" (:expressionType v)))))
      (testing "in the list"
        (is (= "Base URL of the orders service"
               (->> (get-in (call srv "GET" "/environment/variables" :headers admin) [:body :result]) (filter #(= "esv-orders-url" (:_id %))) first :description))))
      (testing "a PUT sets them; a PUT without them goes back to the defaults, as the API does"
        (call srv "PUT" "/environment/variables/esv-x-y" :headers admin :body {:valueBase64 "NQ==" :description "five" :expressionType "int"})
        (let [v (:body (call srv "GET" "/environment/variables/esv-x-y" :headers admin))]
          (is (= ["five" "int"] ((juxt :description :expressionType) v))))
        (call srv "PUT" "/environment/variables/esv-x-y" :headers admin :body {:valueBase64 "Ng=="})
        (is (= ["" "string"] ((juxt :description :expressionType) (:body (call srv "GET" "/environment/variables/esv-x-y" :headers admin))))))
      (finally (server/stop! srv)))))
