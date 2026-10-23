(ns sling.fake-ping-test
  "The fake tenant as the things around it see it: a Frodo export loaded as the tenant, platform
  journeys, a service getting tokens, a browser app doing code + PKCE, Spring Security checking
  the tokens, IDM over REST shared with the journeys, service accounts, modules switched off."
  (:require [cheshire.core :as json]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing use-fixtures]]
            [sling.engine :as engine]
            [sling.frodo :as frodo]
            [sling.idm :as idm]
            [sling.jwt :as jwt]
            [sling.mfa :as mfa]
            [sling.server :as server]
            [sling.web :as web])
  (:import (java.security MessageDigest)
           (java.util Base64)
           (org.springframework.security.oauth2.jwt JwtDecoders)))

(def export "test/fixtures/frodo-export")
(def services "test/fixtures/frodo-services.edn")
(def ^:dynamic *srv* nil)

(use-fixtures :each (fn [t] (let [s (server/start! {:port 0 :frodo export :services services})]
                              (try (binding [*srv* s] (t)) (finally (server/stop! s))))))

(defn- call
  "Through server/handle, no socket. `form` makes a urlencoded body, `body` a JSON one."
  [method path & {:keys [query headers form body]}]
  (let [hs (cond-> (update-vals (update-keys (or headers {}) str/lower-case) vector)
             form (assoc "content-type" ["application/x-www-form-urlencoded"]))
        r (server/handle *srv* {:method method :path path :query (update-vals (or query {}) vector) :headers hs
                                :body (cond form (web/query-string form) body (json/generate-string body) :else "")})]
    (cond-> r (string? (:body r)) (update :body #(if (str/blank? %) % (try (json/parse-string % true) (catch Exception _ %)))))))

(def auth "/am/json/realms/root/realms/alpha/authenticate")
(def oauth "/am/oauth2/realms/root/realms/alpha")
(defn- basic [id secret] {"Authorization" (str "Basic " (.encodeToString (Base64/getEncoder) (.getBytes (str id ":" secret))))})

(defn- login*
  "Drive /authenticate answering each input in order. Returns the last response plus :rounds."
  [& values]
  (loop [r (call "POST" auth :headers {"X-Sling-Debug" "true"}) vs values rounds []]
    (if-let [cbs (get-in r [:body :callbacks])]
      (let [n (count (filter :input cbs))]
        (recur (call "POST" auth :headers {"X-Sling-Debug" "true"}
                     :body {:authId (get-in r [:body :authId]) :callbacks (engine/answer cbs (take n vs))})
               (drop n vs) (conj rounds (mapv :type cbs))))
      (assoc r :rounds rounds))))

(defn- client-token [scope]
  (call "POST" (str oauth "/access_token") :headers (basic "orders-service" "orders-secret")
        :form {:grant_type "client_credentials" :scope scope}))

(deftest frodo-export-is-the-tenant
  (let [t (frodo/load-tenant export "alpha")]
    (is (= #{"PlatformLogin" "Preferences" "OathLogin" "EmailOtp" "ResetPassword"} (set (keys (:trees t)))))
    (is (= "members.test" (get-in t [:services :esv "esv.member.domain"])))
    (is (= #{"orders-web" "orders-service"} (set (keys (:clients t)))))
    (is (every? :runnable? (frodo/coverage t)) "every fixture journey uses only modelled nodes and next-generation scripts")))

(deftest platform-journey
  (testing "page node asks for both at once; members go on to the inner journey"
    (let [r (login* "ana" "Ana-pw-123")]
      (is (= 200 (:status r)))
      (is (= [["NameCallback" "PasswordCallback"]] (:rounds r)))
      (is (= ["Page Node" "Identity Store Decision" "Increment Login Count" "Member check" "Login Count Decision"]
             (mapv :node (get-in r [:body :_sling :trace]))))
      (is (= {"member" "true"} (get-in r [:body :_sling :sessionProperties])))
      (is (re-find #"iPlanetDirectoryPro=AQIC" (first (get-in r [:headers "Set-Cookie"]))))))
  (testing "the third login asks for preferences and writes them to the user"
    (login* "ana" "Ana-pw-123")
    (let [r (login* "ana" "Ana-pw-123" true false)]
      (is (= ["BooleanAttributeInputCallback" "BooleanAttributeInputCallback"] (second (:rounds r))))
      (is (= {:updates true :marketing false}
             (:preferences (idm/read-obj (:idm *srv*) "alpha_user" "3f9a2b1c-0000-4000-8000-000000000001"))))))
  (testing "guests skip it"
    (is (= "guest" (-> (login* "dan" "Dan-pw-123") :body :_sling :trace (nth 3) :outcome))))
  (testing "three wrong passwords lock the account, and then even the right one is refused"
    (let [r (login* "dan" "x" "dan" "x" "dan" "x")]
      (is (= 401 (:status r)))
      (is (= "inactive" (:accountStatus (idm/find-by (:idm *srv*) "alpha_user" :userName "dan"))))
      (is (= "LOCKED" (-> (login* "dan" "Dan-pw-123") :body :_sling :trace last :outcome))))))

(deftest service-tokens
  (let [srv (server/start! {:port 0 :frodo export :services services})
        iss (str (get-in srv [:opts :public-url]) oauth)]
    (try
      (binding [*srv* srv]
        (let [r (client-token "orders:write fr:idm:*")
              tok (get-in r [:body :access_token])]
          (testing "client_credentials gives a JWT with the platform's claims"
            (is (= 200 (:status r)))
            (is (= {:sub "orders-service" :client_id "orders-service" :aud "orders-service" :tokenName "access_token"
                    :realm "/alpha" :scope ["orders:write" "fr:idm:*"] :grant_type "client_credentials" :iss iss}
                   (select-keys (:claims (jwt/decode tok)) [:sub :client_id :aud :tokenName :realm :scope :grant_type :iss]))))
          (testing "Spring Security, configured only with the issuer, accepts it (discovery, jwk_uri, signature, iss, exp)"
            (let [jwt (.decode (JwtDecoders/fromIssuerLocation iss) tok)]
              (is (= "orders-service" (.getSubject jwt)))
              (is (= ["orders:write" "fr:idm:*"] (vec (.getClaimAsStringList jwt "scope"))))))
          (testing "introspection, then revocation"
            (let [in #(call "POST" (str oauth "/introspect") :headers (basic "orders-service" "orders-secret") :form {:token tok})]
              (is (= {:active true :scope "orders:write fr:idm:*" :client_id "orders-service" :realm "/alpha"}
                     (select-keys (:body (in)) [:active :scope :client_id :realm])))
              (is (= 200 (:status (call "POST" (str oauth "/token/revoke") :headers (basic "orders-service" "orders-secret") :form {:token tok}))))
              (is (= {:active false} (:body (in))))))
          (testing "refusals look like the platform's"
            (is (= "invalid_scope" (get-in (client-token "admin:everything") [:body :error])))
            (is (= 401 (:status (call "POST" (str oauth "/access_token") :headers (basic "orders-service" "wrong")
                                      :form {:grant_type "client_credentials"}))))
            (is (= "unauthorized_client" (get-in (call "POST" (str oauth "/access_token") :form {:grant_type "client_credentials" :client_id "orders-web"})
                                                 [:body :error]))))))
      (finally (server/stop! srv)))))

(defn- s256 [v] (jwt/b64url (.digest (MessageDigest/getInstance "SHA-256") (.getBytes ^String v "US-ASCII"))))

(deftest browser-app-code-flow
  (let [srv (server/start! {:port 0 :frodo export :services services})
        iss (str (get-in srv [:opts :public-url]) oauth)
        verifier "a-long-enough-code-verifier-for-pkce-0123456789"
        q {"client_id" "orders-web" "redirect_uri" "http://localhost:5173/callback" "response_type" "code"
           "scope" "openid email orders:read" "state" "xyz" "nonce" "n-1"
           "code_challenge" (s256 verifier) "code_challenge_method" "S256"}]
    (try
      (binding [*srv* srv]
        (testing "no session: sent to the login page, with the way back"
          (let [loc (get-in (call "GET" (str oauth "/authorize") :query q) [:headers "Location"])]
            (is (str/includes? loc "/am/XUI/?realm=/alpha&goto="))))
        (let [cookie (-> (login* "ana" "Ana-pw-123") (get-in [:headers "Set-Cookie"]) first (str/split #";") first)
              loc (get-in (call "GET" (str oauth "/authorize") :query q :headers {"Cookie" cookie}) [:headers "Location"])
              params (web/decode-form (second (str/split loc #"\?" 2)))
              tok (call "POST" (str oauth "/access_token")
                        :form {:grant_type "authorization_code" :client_id "orders-web" :code (first (params "code"))
                               :redirect_uri "http://localhost:5173/callback" :code_verifier verifier})]
          (testing "with a session the code comes back with state and iss"
            (is (= ["xyz"] (params "state")))
            (is (= [iss] (params "iss"))))
          (testing "the code buys tokens; the id token names the user and carries the nonce"
            (is (= 200 (:status tok)))
            (let [idt (.decode (JwtDecoders/fromIssuerLocation iss) (get-in tok [:body :id_token]))]
              (is (= "3f9a2b1c-0000-4000-8000-000000000001" (.getSubject idt)))
              (is (= "ana@members.test" (.getClaimAsString idt "email")))
              (is (= "n-1" (.getClaimAsString idt "nonce")))))
          (testing "userinfo answers from the IDM user"
            (is (= "ana@members.test" (get-in (call "GET" (str oauth "/userinfo")
                                                    :headers {"Authorization" (str "Bearer " (get-in tok [:body :access_token]))})
                                              [:body :email]))))
          (testing "a code works once"
            (is (= "invalid_grant" (get-in (call "POST" (str oauth "/access_token")
                                                 :form {:grant_type "authorization_code" :client_id "orders-web" :code (first (params "code"))
                                                        :redirect_uri "http://localhost:5173/callback" :code_verifier verifier})
                                           [:body :error]))))
          (testing "refresh"
            (is (= 200 (:status (call "POST" (str oauth "/access_token")
                                      :form {:grant_type "refresh_token" :client_id "orders-web"
                                             :refresh_token (get-in tok [:body :refresh_token])})))))))
      (finally (server/stop! srv)))))

(deftest password-grant-runs-the-journey
  (let [ok (call "POST" (str oauth "/access_token") :headers (basic "orders-service" "orders-secret")
                 :form {:grant_type "password" :username "dan" :password "Dan-pw-123" :scope "openid profile"})]
    (is (= 200 (:status ok)))
    (is (= "3f9a2b1c-0000-4000-8000-000000000002" (:sub (:claims (jwt/decode (get-in ok [:body :access_token])))))))
  (is (= "invalid_grant" (get-in (call "POST" (str oauth "/access_token") :headers (basic "orders-service" "orders-secret")
                                       :form {:grant_type "password" :username "dan" :password "nope"})
                                 [:body :error]))))

(deftest idm-over-rest-is-the-journeys-store
  (let [bearer {"Authorization" (str "Bearer " (get-in (client-token "fr:idm:*") [:body :access_token]))}
        users "/openidm/managed/alpha_user"]
    (testing "no token, wrong scope"
      (is (= 401 (:status (call "GET" users :query {"_queryFilter" "true"}))))
      (is (= 403 (:status (call "GET" users :query {"_queryFilter" "true"}
                                :headers {"Authorization" (str "Bearer " (get-in (client-token "orders:write") [:body :access_token]))})))))
    (testing "a service creates a user; the password is never read back"
      (let [r (call "POST" users :query {"_action" "create"} :headers bearer
                    :body {:userName "ioana" :password "Ioana-pw-1" :mail "ioana@members.test" :accountStatus "active"})]
        (is (= 201 (:status r)))
        (is (nil? (get-in r [:body :password])))))
    (testing "and she can log in through the journey straight away"
      (is (= 200 (:status (login* "ioana" "Ioana-pw-1")))))
    (testing "query filters, fields, sorting"
      (let [r (call "GET" users :headers bearer
                    :query {"_queryFilter" "mail co \"members.test\" and accountStatus eq 'active'" "_fields" "userName" "_sortKeys" "-userName"})]
        (is (= ["ioana" "ana"] (mapv :userName (get-in r [:body :result]))))
        (is (= #{:_id :_rev :userName} (set (keys (first (get-in r [:body :result])))))))
      (is (= 400 (:status (call "GET" users :headers bearer :query {"_queryFilter" "userName eq"})))))
    (testing "patch, with revision check (her login already bumped the revision: the journey wrote her login count)"
      (let [{:keys [_id _rev]} (idm/find-by (:idm *srv*) "alpha_user" :userName "ioana")
            r (call "PATCH" (str users "/" _id) :headers (assoc bearer "If-Match" _rev)
                    :body [{:operation "replace" :field "/givenName" :value "Ioana"}])]
        (is (= ["Ioana" "3"] [(get-in r [:body :givenName]) (get-in r [:body :_rev])]))
        (is (= 412 (:status (call "PATCH" (str users "/" _id) :headers (assoc bearer "If-Match" _rev)
                                  :body [{:operation "remove" :field "/givenName"}]))))))))

(deftest service-account-like-frodo
  (let [k (jwt/new-key "sa-key")
        sa "8a4fce63-0000-4000-8000-00000000005a"
        _ (idm/create! (:idm *srv*) "svcacct" {:_id sa :name "deployer" :accountStatus "active" :scopes ["fr:am:*" "fr:idm:*"]
                                               :jwks (json/generate-string (jwt/jwks k))})
        assertion (fn [key] (jwt/sign key {:iss sa :sub sa :aud (str (get-in *srv* [:opts :public-url]) "/am/oauth2/access_token")
                                           :exp (+ (jwt/now) 180) :jti (str (random-uuid))}))
        grant (fn [a scope] (call "POST" "/am/oauth2/access_token"
                                  :form {:grant_type "urn:ietf:params:oauth:grant-type:jwt-bearer" :client_id "service-account"
                                         :assertion a :scope scope}))
        r (grant (assertion k) "fr:am:* fr:idc:esv:*")]
    (testing "an assertion signed with the account's key gets the scopes it has (and only those)"
      (is (= 200 (:status r)))
      (is (= "fr:am:*" (get-in r [:body :scope]))))
    (testing "the token can manage journeys"
      (is (= 200 (:status (call "GET" "/am/json/realms/root/realms/alpha/realm-config/authentication/authenticationtrees/trees"
                                :headers {"Authorization" (str "Bearer " (get-in r [:body :access_token]))})))))
    (testing "another key is refused"
      (is (re-find #"bad signature" (get-in (grant (assertion (jwt/new-key "sa-key")) "fr:am:*") [:body :error_description]))))))

(deftest esv-change-changes-the-journey
  (let [bearer {"Authorization" "Bearer local-dev"}]
    (is (= 200 (:status (call "PUT" "/environment/variables/esv-member-domain" :headers bearer
                              :body {:valueBase64 (.encodeToString (Base64/getEncoder) (.getBytes "elsewhere.test"))}))))
    (is (= "member" (-> (login* "dan" "Dan-pw-123") :body :_sling :trace (nth 3) :outcome)))))

(deftest modules-can-be-off
  (let [srv (server/start! {:port 0 :frodo export :services services :modules #{:oauth}})]
    (try
      (binding [*srv* srv]
        (is (= 200 (:status (call "GET" (str oauth "/.well-known/openid-configuration")))))
        (let [r (call "GET" "/openidm/managed/alpha_user" :query {"_queryFilter" "true"})]
          (is (= 404 (:status r)))
          (is (re-find #"module idm, which is off" (get-in r [:body :message])))))
      (finally (server/stop! srv)))))

(deftest query-filter-grammar
  (let [u {:userName "Ana" :age 30 :roles ["a" "b"] :preferences {:updates true}}
        m? #(idm/matches? (idm/parse-filter %) u)]
    (is (m? "userName eq 'ana'"))
    (is (m? "/preferences/updates eq true and !(/preferences/marketing pr)"))
    (is (m? "(age gt 40) or (age le 30 and roles eq \"b\")"))
    (is (not (m? "false or userName sw 'x'")))
    (is (thrown? clojure.lang.ExceptionInfo (idm/parse-filter "userName eq 'a' and")))))

(defn- orders-service
  "A stand-in for one of our own services, on a real socket: GET /orders, POST /customers."
  [seen]
  (let [s (com.sun.net.httpserver.HttpServer/create (java.net.InetSocketAddress. "127.0.0.1" 0) 0)]
    (.createContext s "/" (reify com.sun.net.httpserver.HttpHandler
                            (handle [_ ex]
                              (let [body (slurp (.getRequestBody ex))
                                    out (.getBytes (if (= "GET" (.getRequestMethod ex))
                                                     "[{\"id\":\"o-1\",\"total\":12.5},{\"id\":\"o-2\",\"total\":3}]"
                                                     "{\"ok\":true}"))]
                                (swap! seen conj [(.getRequestMethod ex) (str (.getRequestURI ex)) body])
                                (.add (.getResponseHeaders ex) "Content-Type" "application/json")
                                (.sendResponseHeaders ex 200 (count out))
                                (with-open [o (.getResponseBody ex)] (.write o out))))))
    (.start s)
    s))

(deftest idm-scripts-run-against-our-services
  (let [seen (atom [])
        svc (orders-service seen)
        bearer {"Authorization" (str "Bearer " (get-in (client-token "fr:idm:*") [:body :access_token]))}]
    (swap! (:tenant *srv*) assoc-in [:services :esv "esv.orders.url"] (str "http://127.0.0.1:" (.getPort (.getAddress svc))))
    (try
      (testing "onCreate shapes the object, postCreate tells our service, whoever creates"
        (let [r (call "POST" "/openidm/managed/alpha_user" :query {"_action" "create"} :headers bearer
                      :body {:userName "eva" :password "Eva-pw-123" :mail "Eva@Members.TEST"})]
          (is (= 201 (:status r)))
          (is (= ["eva@members.test" "created by orders-service"] [(get-in r [:body :mail]) (get-in r [:body :description])]))
          (is (= "POST" (ffirst @seen)))
          (is (= (get-in r [:body :_id]) (:id (json/parse-string (nth (first @seen) 2) true))))))
      (testing "onValidate refuses with the platform's 403"
        (let [r (call "POST" "/openidm/managed/alpha_user" :query {"_action" "create"} :headers bearer :body {:userName "has space"})]
          (is (= 403 (:status r)))
          (is (re-find #"userName has spaces" (get-in r [:body :message])))))
      (testing "a custom endpoint: IDM query + external/rest to our service + ESV + context"
        (let [r (call "GET" "/openidm/endpoint/orderSummary" :query {"user" "ana"} :headers bearer)]
          (is (= 200 (:status r)))
          (is (= {:count 2 :user "ana"} {:count (get-in r [:body :count]) :user (get-in r [:body :user :userName])}))
          (is (= ["GET" "/orders?user=ana"] (subvec (last @seen) 0 2)))))
      (testing "errors thrown by the endpoint keep their code"
        (is (= 404 (:status (call "GET" "/openidm/endpoint/orderSummary" :query {"user" "nobody"} :headers bearer))))
        (is (= 405 (:status (call "DELETE" "/openidm/endpoint/orderSummary" :headers bearer)))))
      (testing "a Groovy managed object script is refused by name"
        (swap! (:tenant *srv*) assoc-in [:managed-schemas "alpha_user" :onUpdate] {:type "groovy" :source "object"})
        (let [id (:_id (idm/find-by (:idm *srv*) "alpha_user" :userName "ana"))
              r (call "PATCH" (str "/openidm/managed/alpha_user/" id) :headers bearer :body [{:operation "replace" :field "/sn" :value "X"}])]
          (is (= 501 (:status r)))
          (is (re-find #"groovy, which sling does not run" (get-in r [:body :message])))))
      (finally (.stop svc 0)))))

(defn- drive
  "Run journey `j` (nil: start from `query` as given), answering each round with (answer callbacks)
  -> values for the inputs. Returns the last response with :rounds (the callback types seen)."
  [query answer]
  (loop [r (call "POST" auth :query query :headers {"X-Sling-Debug" "true"}) rounds []]
    (let [cbs (get-in r [:body :callbacks])]
      (if (and cbs (not= "SuspendedTextOutputCallback" (:type (first cbs))) (< (count rounds) 10))
        (recur (call "POST" auth :headers {"X-Sling-Debug" "true"}
                     :body {:authId (get-in r [:body :authId]) :callbacks (engine/answer cbs (answer cbs))})
               (conj rounds (mapv :type cbs)))
        (assoc r :rounds (conj rounds (mapv :type cbs)))))))

(defn- outbox [] @(get-in @(:tenant *srv*) [:services :outbox]))
(defn- svc [j] {"authIndexType" "service" "authIndexValue" j})

(deftest oath-totp
  (let [answer (fn [code] (fn [cbs]
                            (case (mapv :type cbs)
                              ["NameCallback" "PasswordCallback"] ["ana" "Ana-pw-123"]
                              ["TextOutputCallback" "HiddenValueCallback" "ConfirmationCallback"] [(get-in cbs [1 :output 0 :value]) 0]
                              ["NameCallback"] [(code)])))
        secret #(:secret (last (filter (comp #{"oath-registration"} :kind) (outbox))))]
    (testing "first time: register (the QR's otpauth URI is in the hidden value), then a real TOTP code"
      (let [r (drive (svc "OathLogin") (answer #(mfa/totp (secret))))]
        (is (= 200 (:status r)))
        (is (= [["NameCallback" "PasswordCallback"] ["TextOutputCallback" "HiddenValueCallback" "ConfirmationCallback"] ["NameCallback"]]
               (butlast (:rounds r))))
        (is (str/starts-with? (:uri (last (outbox))) "otpauth://totp/sling:ana?secret="))))
    (testing "next time straight to the code; a wrong one fails"
      (let [r (drive (svc "OathLogin") (answer #(mfa/totp (secret))))]
        (is (= [["NameCallback" "PasswordCallback"] ["NameCallback"]] (butlast (:rounds r))))
        (is (= 200 (:status r))))
      (is (= 401 (:status (drive (svc "OathLogin") (answer (constantly "000000")))))))))

(deftest email-otp
  (let [answer (fn [wrong?] (fn [cbs] (if (= 2 (count cbs)) ["dan" "Dan-pw-123"]
                                          [(if wrong? "nope" (:otp (last (outbox))))])))]
    (is (= 200 (:status (drive (svc "EmailOtp") (answer false)))))
    (is (= {:kind "email" :to "dan@elsewhere.test" :subject "Your code"} (select-keys (last (outbox)) [:kind :to :subject])))
    (is (re-find #"^Your code is \d{6}\.$" (:body (last (outbox)))))
    (is (= 401 (:status (drive (svc "EmailOtp") (answer true)))))))

(deftest reset-password-by-mail-link
  (let [r (drive (svc "ResetPassword") (constantly ["ana"]))
        mail (last (outbox))
        sid (second (re-find #"suspendedId=(\w+)" (:resumeURI mail)))]
    (testing "the journey stops and says so; the link is in the mail"
      (is (= "SuspendedTextOutputCallback" (get-in r [:body :callbacks 0 :type])))
      (is (= ["ana@members.test" "Reset your password"] [(:to mail) (:subject mail)]))
      (is (str/includes? (:body mail) "Hello Ana")))
    (testing "the link resumes it, the new password is saved, and works"
      (let [r2 (call "POST" auth :query {"suspendedId" sid})
            cbs (get-in r2 [:body :callbacks])]
        (is (= ["ValidatedCreatePasswordCallback"] (mapv :type cbs)))
        (is (= 200 (:status (call "POST" auth :body {:authId (get-in r2 [:body :authId]) :callbacks (engine/answer cbs ["New-pw-456"])}))))
        (is (= 200 (:status (login* "ana" "New-pw-456"))))
        (is (= 401 (:status (call "POST" auth :query {"suspendedId" sid}))) "a link works once")))))

(defn- json-server
  "Serve one JSON document on a real local port (a jwks_uri, say)."
  [doc]
  (let [s (com.sun.net.httpserver.HttpServer/create (java.net.InetSocketAddress. "127.0.0.1" 0) 0)]
    (.createContext s "/" (reify com.sun.net.httpserver.HttpHandler
                            (handle [_ ex]
                              (let [out (.getBytes (json/generate-string doc))]
                                (.sendResponseHeaders ex 200 (count out))
                                (with-open [o (.getResponseBody ex)] (.write o out))))))
    (.start s)
    s))

(deftest clients-with-key-pairs
  (let [k (jwt/new-key "batch-1")
        token-url (str (get-in *srv* [:opts :public-url]) oauth "/access_token")
        jwks-srv (json-server (jwt/jwks k))
        assertion (fn [key] (jwt/sign key {:iss "orders-batch" :sub "orders-batch" :aud token-url
                                           :exp (+ (jwt/now) 60) :jti (str (random-uuid))}))
        grant (fn [a] (call "POST" (str oauth "/access_token")
                            :form {:grant_type "client_credentials" :scope "orders:write"
                                   :client_assertion_type "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                                   :client_assertion a}))]
    (try
      (doseq [[how cfg] {"inline JWK set" {:jwkSet (json/generate-string (jwt/jwks k)) :publicKeyLocation "jwks"}
                         "jwks_uri on our own service" {:jwksUri (str "http://127.0.0.1:" (.getPort (.getAddress jwks-srv)) "/jwks")
                                                        :publicKeyLocation "jwks_uri"}}]
        (swap! (:tenant *srv*) assoc-in [:clients "orders-batch"]
               {:coreOAuth2ClientConfig {:clientType "Confidential" :scopes ["orders:write"]}
                :advancedOAuth2ClientConfig {:grantTypes ["client_credentials"] :tokenEndpointAuthMethod "private_key_jwt"}
                :signEncOAuth2ClientConfig cfg})
        (testing (str "private_key_jwt, " how)
          (is (= 200 (:status (grant (assertion k)))))
          (is (= 401 (:status (grant (assertion (jwt/new-key "batch-1"))))) "someone else's key")))
      (finally (.stop jwks-srv 0)))))

(deftest trusted-issuer-jwt-grant
  (let [k (jwt/new-key "idp-1")
        aud (str (get-in *srv* [:opts :public-url]) oauth "/access_token")
        jwt (fn [claims] (jwt/sign k (merge {:iss "https://idp.example.test" :sub "ana" :aud aud :exp (+ (jwt/now) 60) :scope ["openid"]} claims)))
        grant (fn [a] (call "POST" (str oauth "/access_token") :headers (basic "orders-service" "orders-secret")
                            :form {:grant_type "urn:ietf:params:oauth:grant-type:jwt-bearer" :assertion a :scope "openid"}))]
    (swap! (:tenant *srv*) assoc :trusted-issuers {"idp" {:issuer "https://idp.example.test" :jwkSet (json/generate-string (jwt/jwks k))
                                                         :consentedScopesClaim "scope" :allowedSubjects []}})
    (swap! (:tenant *srv*) update-in [:services :clients "orders-service" :grantTypes]
           (constantly ["client_credentials" "password" "urn:ietf:params:oauth:grant-type:jwt-bearer"]))
    (let [r (grant (jwt {}))]
      (is (= 200 (:status r)))
      (is (= "3f9a2b1c-0000-4000-8000-000000000001" (:sub (:claims (jwt/decode (get-in r [:body :access_token])))))))
    (is (re-find #"no trusted JWT issuer" (get-in (grant (jwt {:iss "https://evil.test"})) [:body :error_description])))
    (is (= "invalid_scope" (get-in (grant (jwt {:scope ["profile"]})) [:body :error])) "scope not consented in the assertion")))

(deftest sync-to-our-database
  (let [bearer {"Authorization" (str "Bearer " (get-in (client-token "fr:idm:*") [:body :access_token]))}
        accounts "/openidm/system/HRDB/__ACCOUNT__"
        in-db (fn [] (mapv #(select-keys % [:__NAME__ :fullname :organization :email])
                           (get-in (call "GET" accounts :query {"_queryFilter" "true" "_sortKeys" "__NAME__"} :headers bearer) [:body :result])))
        user (fn [name] (idm/find-by (:idm *srv*) "alpha_user" :userName name))]
    (testing "a new active user reaches the HR system: properties, transform, the mapping's onCreate"
      (call "POST" "/openidm/managed/alpha_user" :query {"_action" "create"} :headers bearer
            :body {:userName "mara" :givenName "Mara" :sn "Dobre" :mail "mara@members.test" :accountStatus "active"})
      (is (= [{:__NAME__ "mara" :fullname "Mara Dobre" :organization "WEB" :email "mara@members.test"}] (in-db))))
    (testing "a change follows (CONFIRMED -> UPDATE)"
      (call "PATCH" (str "/openidm/managed/alpha_user/" (:_id (user "mara"))) :headers bearer
            :body [{:operation "replace" :field "/sn" :value "Popa"}])
      (is (= "Mara Popa" (:fullname (first (in-db))))))
    (testing "deactivated: no longer a valid source (UNQUALIFIED -> DELETE)"
      (call "PATCH" (str "/openidm/managed/alpha_user/" (:_id (user "mara"))) :headers bearer
            :body [{:operation "replace" :field "/accountStatus" :value "inactive"}])
      (is (= [] (in-db))))
    (testing "a row that appears in the HR system becomes a user, linked both ways, no duplicate pushed back"
      (call "POST" accounts :query {"_action" "create"} :headers bearer
            :body {:__NAME__ "ilie" :firstname "Ilie" :lastname "Stan" :email "ilie@hr.test"})
      (is (= {:userName "ilie" :givenName "Ilie" :mail "ilie@hr.test" :accountStatus "active"}
             (select-keys (user "ilie") [:userName :givenName :mail :accountStatus])))
      (is (= ["ilie"] (mapv :__NAME__ (in-db)))))
    (testing "recon pushes the users that were there before"
      (let [r (call "POST" "/openidm/recon" :query {"_action" "recon" "mapping" "alphaUser_systemHrdbAccount"} :headers bearer)]
        (is (= 200 (:status r)))
        (is (= #{"ana" "dan" "ilie"} (set (map :__NAME__ (in-db)))))
        (is (= ["CREATE" "CREATE" "UPDATE"] (sort (keep :action (get-in r [:body :results])))) "mara is inactive: nothing to do")))
    (testing "deleting the user deletes the row (SOURCE_MISSING -> DELETE)"
      (call "DELETE" (str "/openidm/managed/alpha_user/" (:_id (user "dan"))) :headers bearer)
      (is (= #{"ana" "ilie"} (set (map :__NAME__ (in-db))))))
    (testing "the ESV behind enableSync switches the mapping off"
      (swap! (:tenant *srv*) assoc-in [:services :esv "esv.hrdb.sync"] "false")
      (call "POST" "/openidm/managed/alpha_user" :query {"_action" "create"} :headers bearer
            :body {:userName "off" :accountStatus "active"})
      (is (not (contains? (set (map :__NAME__ (in-db))) "off"))))
    (testing "GET /sling/sync shows what happened"
      (is (seq (get-in (call "GET" "/sling/sync") [:body :result]))))))

(deftest console-made-correlation
  (testing "an expression tree from the admin console correlates without its UI script"
    (swap! (:tenant *srv*) update :mappings
           (fn [ms] (mapv #(if (= "alphaUser_systemHrdbAccount" (:name %))
                             (assoc % :correlationQuery [{:expressionTree {:all ["__NAME__"]} :file "ui/correlateTreeToQueryFilter.js"
                                                          :linkQualifier "default" :type "text/javascript"}])
                             %) ms)))
    (let [bearer {"Authorization" "Bearer local-dev"}]
      (idm/create! (:idm *srv*) "system/HRDB/__ACCOUNT__" {:__NAME__ "toma" :email "old@hr.test"})
      (call "POST" "/openidm/managed/alpha_user" :query {"_action" "create"} :headers bearer
            :body {:userName "toma" :mail "toma@members.test" :accountStatus "active"})
      (is (= [["toma" "toma@members.test"]]
             (mapv (juxt :__NAME__ :email) (vals (get @(:idm *srv*) "system/HRDB/__ACCOUNT__"))))
          "found the existing row and updated it, no second row"))))

(deftest idm-config-over-rest
  (let [bearer {"Authorization" "Bearer local-dev"}]
    (testing "PUT a custom endpoint (as frodo idm import does) and it runs"
      (is (= 200 (:status (call "PUT" "/openidm/config/endpoint/hello" :headers bearer
                                :body {:type "text/javascript" :source "({ hello: request.additionalParameters.name });"}))))
      (is (= {:hello "you"} (:body (call "GET" "/openidm/endpoint/hello" :query {"name" "you"} :headers bearer)))))
    (testing "PUT managed replaces the object scripts"
      (let [managed (:body (call "GET" "/openidm/config/managed" :headers bearer))
            changed (update managed :objects (fn [os] (mapv #(assoc % :onCreate {:type "text/javascript" :source "object.sn = 'FROM CONFIG';"}) os)))]
        (call "PUT" "/openidm/config/managed" :headers bearer :body changed)
        (is (= "FROM CONFIG" (get-in (call "POST" "/openidm/managed/alpha_user" :query {"_action" "create"} :headers bearer
                                           :body {:userName "cfg"}) [:body :sn])))))
    (testing "the listing Frodo exports from"
      (is (= #{"endpoint/orderSummary" "endpoint/hello" "managed" "sync" "provisioner.openicf/HRDB"}
             (set (map :_id (get-in (call "GET" "/openidm/config" :query {"_queryFilter" "true"} :headers bearer) [:body :result]))))))))

(defn- hrdb-up? []
  (try (with-open [_ (java.net.Socket. "127.0.0.1" 15432)] true) (catch Exception _ false)))

(deftest sync-through-the-real-connector
  (if-not (hrdb-up?)
    (println "SKIPPED sync-through-the-real-connector: no HR database on 127.0.0.1:15432 (bb hrdb:up)")
    (let [bearer {"Authorization" "Bearer local-dev"}
          rows #(with-open [c (java.sql.DriverManager/getConnection "jdbc:postgresql://127.0.0.1:15432/hr" "hr" "hr")]
                  (let [rs (.executeQuery (.createStatement c) "SELECT username, full_name, department FROM employees ORDER BY id")]
                    (loop [acc []] (if (.next rs) (recur (conj acc [(.getString rs 1) (.getString rs 2) (.getString rs 3)])) acc))))
          clean! #(with-open [c (java.sql.DriverManager/getConnection "jdbc:postgresql://127.0.0.1:15432/hr" "hr" "hr")]
                    (.executeUpdate (.createStatement c) "DELETE FROM employees WHERE username <> 'greta'"))]
      (clean!)
      ;; on a laptop: the same provisioner as the tenant's, pointed at the local scripts and database
      (swap! (:tenant *srv*) assoc-in [:services :connectors "HRDB"]
             {:scriptRoots ["test/fixtures/connectors/hrdb"] :url "jdbc:postgresql://127.0.0.1:15432/hr"
              :driverClassName "org.postgresql.Driver" :username "hr" :password "hr" :validationQuery "SELECT 1"})
      (try
        (testing "a new user goes through the mapping, the Groovy CreateScript, into Postgres"
          (call "POST" "/openidm/managed/alpha_user" :query {"_action" "create"} :headers bearer
                :body {:userName "petra" :givenName "Petra" :sn "Vlad" :mail "petra@members.test" :accountStatus "active"})
          (is (= [["greta" "Greta Nagy" "FIN"] ["petra" "Petra Vlad" "WEB"]] (rows))))
        (testing "a change: SearchScript for the link, UpdateScript for the row"
          (call "PATCH" (str "/openidm/managed/alpha_user/" (:_id (idm/find-by (:idm *srv*) "alpha_user" :userName "petra")))
                :headers bearer :body [{:operation "replace" :field "/sn" :value "Lungu"}])
          (is (= ["petra" "Petra Lungu" "WEB"] (second (rows)))))
        (testing "the rows read back over /openidm/system with a query filter (SearchScript's WHERE)"
          (is (= ["greta"] (mapv :__NAME__ (get-in (call "GET" "/openidm/system/HRDB/__ACCOUNT__" :headers bearer
                                                         :query {"_queryFilter" "email sw \"greta\""}) [:body :result])))))
        (testing "recon creates users from rows that were there first (reverse mapping)"
          (call "POST" "/openidm/recon" :query {"_action" "recon" "mapping" "systemHrdbAccount_alphaUser"} :headers bearer)
          (is (= "greta@hr.test" (:mail (idm/find-by (:idm *srv*) "alpha_user" :userName "greta")))))
        (testing "deleting the user: DeleteScript removes the row"
          (call "DELETE" (str "/openidm/managed/alpha_user/" (:_id (idm/find-by (:idm *srv*) "alpha_user" :userName "petra"))) :headers bearer)
          (is (= [["greta" "Greta Nagy" "FIN"]] (rows))))
        (finally (clean!))))))

(deftest sms-otp
  (let [t @(:tenant *srv*)
        tree (get-in t [:trees "EmailOtp"])
        sender (some (fn [[id n]] (when (= "OneTimePasswordSmtpSenderNode" (:nodeType n)) (name id))) (:nodes tree))]
    ;; the same journey with the SMS sender in the mail sender's place
    (swap! (:tenant *srv*) assoc-in [:trees "SmsOtp"]
           (assoc-in tree [:nodes (keyword sender) :nodeType] "OneTimePasswordSmsSenderNode"))
    (swap! (:tenant *srv*) assoc-in [:nodes sender :smsContent] {:en "Code: {{OTP}}"})
    (idm/patch! (:idm *srv*) "alpha_user" "3f9a2b1c-0000-4000-8000-000000000002"
                [{:operation "replace" :field "/telephoneNumber" :value "+40700000001"}])
    (let [r (drive (svc "SmsOtp") (fn [cbs] (if (= 2 (count cbs)) ["dan" "Dan-pw-123"] [(:otp (last (outbox)))])))]
      (is (= 200 (:status r)))
      (is (= {:kind "sms" :to "+40700000001"} (select-keys (last (outbox)) [:kind :to])))
      (is (re-find #"^Code: \d{6}$" (:body (last (outbox))))))))
