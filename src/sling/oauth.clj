(ns sling.oauth
  "The OAuth 2.0 / OpenID Connect provider on the tenant's own URLs, for the services and lambdas
  that only need tokens:

    GET  /am/oauth2[/realms/root/realms/<r>]/.well-known/openid-configuration
    GET  .../connect/jwk_uri
    GET|POST .../authorize            response_type=code, PKCE plain/S256, needs the SSO cookie
    POST .../access_token             client_credentials, password, authorization_code, refresh_token,
                                      jwt-bearer (service accounts, root realm, as Frodo logs in)
    POST .../introspect               RFC 7662 plus the platform's extra fields
    GET|POST .../userinfo
    POST .../token/revoke
    GET  .../connect/endSession

  Tokens are RS256 JWTs with the claims the docs show for client-side tokens (tokenName, subname,
  realm, scope as a list, authGrantId ...), or opaque strings with {:token-format :opaque}. Either
  way the server remembers them, so introspection and revocation behave.

  Clients come from the tenant (the realm's OAuth2 client exports, as Frodo writes them) merged
  with :clients in services.edn, which is where secrets live, since exports never carry them."
  (:require [cheshire.core :as json]
            [clojure.string :as str]
            [sling.engine :as engine]
            [sling.idm :as idm]
            [sling.jwt :as jwt]
            [sling.outside :as outside]
            [sling.web :as web])
  (:import (java.security MessageDigest)
           (java.util UUID)))

(defn realm-path [realm] (if (or (nil? realm) (= realm "root")) "" (str "/realms/root/realms/" realm)))
(defn issuer [{:keys [opts]} realm] (str (:public-url opts) "/am/oauth2" (realm-path realm)))

(defn- rand-id [] (str/replace (str (UUID/randomUUID) (UUID/randomUUID)) "-" ""))

;; ---- clients -------------------------------------------------------------------------------

(defn- v
  "Exports wrap some values as {:inherited false :value x}; take x either way."
  [x] (if (and (map? x) (contains? x :value)) (:value x) x))

(defn client-view
  "One client as this module uses it, from an export-shaped config and/or a services.edn entry."
  [id exported local]
  (let [core (:coreOAuth2ClientConfig exported)
        adv (:advancedOAuth2ClientConfig exported)
        sig (:signEncOAuth2ClientConfig exported)]
    (merge {:id id
            :type (or (v (:clientType core)) "Confidential")
            :secret (v (:userpassword core))
            :scopes (vec (v (:scopes core)))
            :default-scopes (vec (v (:defaultScopes core)))
            :redirect-uris (vec (v (:redirectionUris core)))
            :grant-types (vec (or (v (:grantTypes adv)) ["authorization_code"]))
            :auth-method (or (v (:tokenEndpointAuthMethod adv)) "client_secret_basic")
            :jwks (when-not (= "jwks_uri" (v (:publicKeyLocation sig))) (some-> (v (:jwkSet sig)) (json/parse-string true)))
            :jwks-uri (when (= "jwks_uri" (v (:publicKeyLocation sig))) (v (:jwksUri sig)))
            :access-ttl (let [t (v (:accessTokenLifetime core))] (when (and t (pos? t)) t))}
           (when local
             (cond-> {}
               (:secret local) (assoc :secret (:secret local))
               (:scopes local) (assoc :scopes (:scopes local))
               (:defaultScopes local) (assoc :default-scopes (:defaultScopes local))
               (:redirectUris local) (assoc :redirect-uris (:redirectUris local))
               (:grantTypes local) (assoc :grant-types (:grantTypes local))
               (:clientType local) (assoc :type (:clientType local))
               (:jwks local) (assoc :jwks (:jwks local)))))))

(defn clients [t]
  (let [ids (into (set (keys (:clients t))) (keys (get-in t [:services :clients])))]
    (into {} (for [id ids] [id (client-view id (get-in t [:clients id]) (get-in t [:services :clients id]))]))))

(defn key-set
  "The JWK set of a client or trusted issuer: inline, or fetched from its jwks URI (through
  sling.outside, so a fake or a local service answers)."
  [srv {:keys [jwks jwks-uri]}]
  (or jwks
      (when jwks-uri
        (let [r (outside/http (:services @(:tenant srv)) {:uri jwks-uri :method "GET"})]
          (when (= 200 (:status r)) (json/parse-string (:body r) true))))))

(defn- assertion-ok?
  "RFC 7523 client authentication: signed by the client's key, iss = sub = client_id, aud = the
  token endpoint (or the issuer)."
  [srv realm c assertion]
  (let [ks (key-set srv c)
        claims (some-> assertion jwt/decode :claims)]
    (and ks (= (:id c) (:iss claims) (:sub claims))
         (some #(:ok (jwt/verify assertion ks :aud %)) [(str (issuer srv realm) "/access_token") (issuer srv realm)]))))

(defn- authenticate-client
  "{:client c} or {:error response}. Accepts client_secret_basic, client_secret_post,
  private_key_jwt and, for public clients, client_id alone."
  [srv realm req]
  (let [cs (clients @(:tenant srv))
        [bid bsecret] (web/basic req)
        f #(web/form1 req %)
        assertion (f "client_assertion")
        aclaims (some-> assertion jwt/decode :claims)
        id (or bid (f "client_id") (:sub aclaims))
        c (get cs id)
        bad (web/oauth-error 401 "invalid_client" "Client authentication failed")]
    (cond
      (nil? c) {:error bad}
      bid (if (= bsecret (:secret c)) {:client c} {:error bad})
      (f "client_secret") (if (= (f "client_secret") (:secret c)) {:client c} {:error bad})
      assertion (if (assertion-ok? srv realm c assertion) {:client c} {:error bad})
      (= "Public" (:type c)) {:client c}
      :else {:error bad})))

;; ---- tokens --------------------------------------------------------------------------------

(defn- scope-list [s] (vec (remove str/blank? (str/split (or s "") #"\s+"))))

(defn- grant-scope
  "Requested scopes the client may have, or its defaults when it asked for none. nil = refused."
  [allowed defaults requested]
  (let [req (scope-list requested)]
    (cond
      (empty? req) (vec defaults)
      (every? (set allowed) req) req
      :else nil)))

(defn- user-claims [user scopes]
  (let [s (set scopes)
        g #(let [x (get user %)] (if (sequential? x) (first x) x))]
    (cond-> {}
      (s "profile") (merge (into {} (remove (comp nil? val)
                                            {:given_name (g :givenName) :family_name (g :sn)
                                             :name (or (g :cn) (some->> [(g :givenName) (g :sn)] (remove nil?) seq (str/join " ")))})))
      (s "email") (cond-> (g :mail) (assoc :email (g :mail)))
      (s "phone") (cond-> (g :telephoneNumber) (assoc :phone_number (g :telephoneNumber))))))

(defn- issue
  "Mint tokens for a grant. g: {:client c :realm r :sub s :subname n :scope [..] :grant str
  :auth-time t :nonce n :user obj :refresh? bool}. Returns the token endpoint's JSON body."
  [{:keys [key tokens opts] :as srv} {:keys [client realm sub subname scope grant auth-time nonce user refresh?]}]
  (let [now (jwt/now)
        ttl (or (:access-ttl client) (:access-ttl opts) 3600)
        iss (issuer srv realm)
        grant-id (rand-id)
        claims {:sub sub :cts "OAUTH2_STATELESS_GRANT" :auth_level 0 :auditTrackingId (str (UUID/randomUUID))
                :subname subname :iss iss :tokenName "access_token" :token_type "Bearer" :authGrantId grant-id
                :client_id (:id client) :aud (:id client) :nbf now :grant_type grant :scope scope
                :auth_time (or auth-time now) :realm (str "/" (or realm "root")) :exp (+ now ttl) :iat now
                :expires_in ttl :jti (rand-id)}
        at (if (= :opaque (:token-format opts)) (rand-id) (jwt/sign key claims))
        rt (when refresh? (rand-id))
        idt (when (some #{"openid"} scope)
              (jwt/sign key (merge {:sub sub :auditTrackingId (:auditTrackingId claims) :subname subname :iss iss
                                    :tokenName "id_token" :aud (:id client) :azp (:id client) :acr "0"
                                    :auth_time (or auth-time now) :realm (:realm claims) :exp (+ now ttl) :iat now
                                    :tokenType "JWTToken"}
                                   (when nonce {:nonce nonce})
                                   (user-claims user scope))))]
    (swap! tokens assoc at {:kind :access :claims claims})
    (when rt (swap! tokens assoc rt {:kind :refresh :grant (dissoc (assoc claims :user user) :jti) :grant-id grant-id}))
    (cond-> {:access_token at :scope (str/join " " scope) :token_type "Bearer" :expires_in ttl}
      rt (assoc :refresh_token rt)
      idt (assoc :id_token idt))))

(defn token-claims
  "Claims of a live access token we issued (JWT or opaque), or nil."
  [{:keys [tokens key]} token]
  (when-let [{:keys [kind claims]} (get @tokens token)]
    (when (and (= kind :access) (> (:exp claims) (jwt/now))
               (or (not (jwt/decode token)) (:ok (jwt/verify token (jwt/jwks key)))))
      claims)))

(defn scopes-of [claims] (set (:scope claims)))

;; ---- grants --------------------------------------------------------------------------------

(defn- user-by-name [srv realm username]
  (idm/find-by (:idm srv) (str realm "_user") :userName username))

(defn- password-grant
  "Resource owner password: run the realm's default journey and answer its name and password
  callbacks, as the platform does. A journey that asks for anything else refuses the grant."
  [srv realm client req]
  (let [t @(:tenant srv)
        username (web/form1 req "username")
        password (web/form1 req "password")
        journey (or (get-in t [:services :default-journey]) "Login")]
    (loop [res (engine/start t journey {:headers (:headers req) :parameters {} :cookies {}}) n 0]
      (cond
        (= :success (:status res))
        (if-let [scope (grant-scope (:scopes client) (:default-scopes client) (web/form1 req "scope"))]
          (let [u (user-by-name srv realm username)]
            (web/json 200 (issue srv {:client client :realm realm :sub (or (:_id u) username) :subname (or (:_id u) username)
                                      :scope scope :grant "password" :user u :refresh? true})))
          (web/oauth-error 400 "invalid_scope" "Unknown/invalid scope(s)"))

        (and (= :callbacks (:status res)) (< n 5)
             (every? #{"NameCallback" "PasswordCallback"} (map :type (filter :input (:callbacks res)))))
        (recur (engine/resume t (:session res)
                              (mapv #(if (:input %)
                                       (assoc-in % [:input 0 :value] (if (= "NameCallback" (:type %)) username password))
                                       %)
                                    (:callbacks res)))
               (inc n))

        :else (web/oauth-error 400 "invalid_grant" (str "the journey " journey " did not end in a session"
                                                        (when-let [r (:reason res)] (str ": " r))))))))

(defn- pkce-ok? [{:keys [challenge method]} verifier]
  (cond
    (nil? challenge) true
    (nil? verifier) false
    (= "S256" method) (= challenge (jwt/b64url (.digest (MessageDigest/getInstance "SHA-256") (.getBytes ^String verifier "US-ASCII"))))
    :else (= challenge verifier)))

(defn- code-grant [{:keys [codes] :as srv} realm client req]
  (let [code (web/form1 req "code")
        c (get @codes code)]
    (swap! codes dissoc code)
    (cond
      (or (nil? c) (< (:exp c) (jwt/now)) (not= (:client c) (:id client)))
      (web/oauth-error 400 "invalid_grant" "The provided access grant is invalid, expired, or revoked.")
      (not= (:redirect-uri c) (web/form1 req "redirect_uri"))
      (web/oauth-error 400 "invalid_grant" "redirect_uri does not match the one used at /authorize")
      (not (pkce-ok? c (web/form1 req "code_verifier")))
      (web/oauth-error 400 "invalid_grant" "code_verifier does not match the code_challenge")
      :else
      (web/json 200 (issue srv {:client client :realm realm :sub (:sub c) :subname (:sub c) :scope (:scope c)
                                :grant "authorization_code" :auth-time (:auth-time c) :nonce (:nonce c)
                                :user (:user c) :refresh? true})))))

(defn- refresh-grant [{:keys [tokens] :as srv} realm client req]
  (let [rt (web/form1 req "refresh_token")
        {:keys [kind grant]} (get @tokens rt)]
    (if (and (= kind :refresh) (= (:client_id grant) (:id client)))
      (let [scope (or (grant-scope (:scope grant) (:scope grant) (web/form1 req "scope")) (:scope grant))]
        (swap! tokens dissoc rt)
        (web/json 200 (issue srv {:client client :realm realm :sub (:sub grant) :subname (:subname grant)
                                  :scope scope :grant (:grant_type grant) :auth-time (:auth_time grant)
                                  :user (:user grant) :refresh? true})))
      (web/oauth-error 400 "invalid_grant" "grant is invalid"))))

(defn- service-account-grant
  "The jwt-bearer grant Frodo and other automation use: client_id=service-account and an assertion
  signed with the key whose public half is on managed/svcacct/<id>."
  [srv realm req]
  (let [assertion (web/form1 req "assertion")
        {:keys [claims]} (jwt/decode assertion)
        sa (some->> (:iss claims) (idm/read-obj (:idm srv) "svcacct"))
        jwks (some-> (:jwks sa) (#(if (string? %) (json/parse-string % true) %)))
        check (when jwks (jwt/verify assertion jwks :aud (str (issuer srv realm) "/access_token")))]
    (cond
      (nil? sa) (web/oauth-error 400 "invalid_grant" (str "no service account " (pr-str (:iss claims))))
      (not= "active" (:accountStatus sa)) (web/oauth-error 400 "invalid_grant" "service account is not active")
      (:error check) (web/oauth-error 400 "invalid_grant" (str "assertion refused: " (:error check)))
      :else
      (let [scope (vec (filter (set (:scopes sa)) (scope-list (web/form1 req "scope"))))]
        (if (empty? scope)
          (web/oauth-error 400 "invalid_scope" "none of the requested scopes is granted to this service account")
          (web/json 200 (dissoc (issue srv {:client {:id "service-account"} :realm realm :sub (:_id sa) :subname (:name sa)
                                            :scope scope :grant "urn:ietf:params:oauth:grant-type:jwt-bearer"})
                                :refresh_token)))))))

(defn- trusted-issuer-grant
  "RFC 7523 authorization grant: an assertion from a trusted JWT issuer (realm-config
  TrustedJwtIssuer) names the resource owner; the client gets a token for them."
  [srv realm client req]
  (let [assertion (web/form1 req "assertion")
        claims (:claims (jwt/decode assertion))
        v #(if (and (map? %) (contains? % :value)) (:value %) %)
        ti (first (filter #(= (:iss claims) (v (:issuer %))) (vals (:trusted-issuers @(:tenant srv)))))
        ks (when ti (key-set srv {:jwks (some-> (v (:jwkSet ti)) (#(if (string? %) (json/parse-string % true) %)))
                                  :jwks-uri (v (:jwksUri ti))}))
        check (when ks (jwt/verify assertion ks :aud [(str (issuer srv realm) "/access_token") (issuer srv realm)]))
        owner (get claims (keyword (or (v (:resourceOwnerIdentityClaim ti)) "sub")))
        allowed (seq (v (:allowedSubjects ti)))
        consented (let [c (get claims (keyword (or (v (:consentedScopesClaim ti)) "scope")))]
                    (when c (set (if (string? c) (str/split c #"\s+") c))))]
    (cond
      (nil? ti) (web/oauth-error 400 "invalid_grant" (str "no trusted JWT issuer for " (pr-str (:iss claims))))
      (or (nil? check) (:error check)) (web/oauth-error 400 "invalid_grant" (str "assertion refused: " (or (:error check) "no keys")))
      (and allowed (not (some #{owner} allowed))) (web/oauth-error 400 "invalid_grant" (str "subject " owner " is not allowed"))
      :else
      (if-let [scope (grant-scope (cond->> (:scopes client) consented (filter consented)) (:default-scopes client) (web/form1 req "scope"))]
        (let [u (or (idm/read-obj (:idm srv) (str realm "_user") owner) (user-by-name srv realm owner))]
          (web/json 200 (issue srv {:client client :realm realm :sub (or (:_id u) owner) :subname (or (:_id u) owner)
                                    :scope scope :grant "urn:ietf:params:oauth:grant-type:jwt-bearer" :user u})))
        (web/oauth-error 400 "invalid_scope" "Unknown/invalid scope(s)")))))

(defn- token-endpoint [srv realm req]
  (let [grant (web/form1 req "grant_type")]
    (if (and (= grant "urn:ietf:params:oauth:grant-type:jwt-bearer") (= "service-account" (web/form1 req "client_id")))
      (service-account-grant srv realm req)
      (let [{:keys [client error]} (authenticate-client srv realm req)]
        (cond
          error error
          (not (some #{grant} (:grant-types client)))
          (web/oauth-error 400 "unauthorized_client" (str "client " (:id client) " may not use grant " grant))
          :else
          (case grant
            "client_credentials"
            (if-let [scope (grant-scope (:scopes client) (:default-scopes client) (web/form1 req "scope"))]
              (web/json 200 (issue srv {:client client :realm realm :sub (:id client) :subname (:id client)
                                        :scope scope :grant grant}))
              (web/oauth-error 400 "invalid_scope" "Unknown/invalid scope(s)"))
            "password" (password-grant srv realm client req)
            "authorization_code" (code-grant srv realm client req)
            "refresh_token" (refresh-grant srv realm client req)
            "urn:ietf:params:oauth:grant-type:jwt-bearer" (trusted-issuer-grant srv realm client req)
            (web/oauth-error 400 "unsupported_grant_type" (str "grant_type " (pr-str grant) " is not supported here"))))))))

;; ---- authorize -----------------------------------------------------------------------------

(defn sso-session [{:keys [sso opts]} req]
  (let [id (or (get (web/cookies req) (:cookie-name opts)) (web/header req (:cookie-name opts)))]
    (when-let [s (get @sso id)] (assoc s :tokenId id))))

(defn- authorize [{:keys [codes opts] :as srv} realm req]
  (let [p #(web/form1 req %)
        client (get (clients @(:tenant srv)) (p "client_id"))
        redirect (p "redirect_uri")
        back (fn [m] (web/redirect (str redirect (if (str/includes? redirect "?") "&" "?")
                                        (web/query-string (assoc m :iss (issuer srv realm) :client_id (p "client_id")
                                                                 :state (p "state"))))))
        session (sso-session srv req)]
    (cond
      (nil? client) (web/error 400 (str "unknown client_id " (pr-str (p "client_id"))))
      (not (some #{redirect} (:redirect-uris client))) (web/error 400 (str "redirect_uri " (pr-str redirect) " is not registered for " (:id client)))
      (not= "code" (p "response_type")) (back {:error "unsupported_response_type" :error_description "only response_type=code here"})
      (nil? session)
      (if (= "none" (p "prompt"))
        (back {:error "login_required" :error_description "no session"})
        (web/redirect (str (:public-url opts) "/am/XUI/?realm=/" (or realm "root") "&goto="
                           (web/url-encode (str (issuer srv realm) "/authorize?" (web/query-string (update-vals (web/form req) first)))))))
      :else
      (if-let [scope (grant-scope (:scopes client) (:default-scopes client) (p "scope"))]
        (let [code (rand-id)]
          (swap! codes assoc code {:client (:id client) :redirect-uri redirect :scope scope :sub (:user-id session)
                                   :user (:user session) :auth-time (:auth-time session) :nonce (p "nonce")
                                   :challenge (p "code_challenge") :method (p "code_challenge_method")
                                   :exp (+ (jwt/now) 120)})
          (back {:code code}))
        (back {:error "invalid_scope" :error_description "Unknown/invalid scope(s)"})))))

;; ---- introspect, userinfo, revoke, discovery -----------------------------------------------

(defn- introspect [srv realm req]
  (let [{:keys [client error]} (authenticate-client srv realm req)
        claims (token-claims srv (web/form1 req "token"))]
    (cond
      error error
      (nil? claims) (web/json 200 {:active false})
      (not (or (= (:client_id claims) (:id client)) (some #{"am-introspect-all-tokens"} (:scopes client))))
      (web/json 200 {:active false})
      :else
      (web/json 200 {:active true :scope (str/join " " (:scope claims)) :realm (:realm claims)
                     :client_id (:client_id claims) :user_id (:sub claims) :username (:subname claims)
                     :token_type "Bearer" :exp (:exp claims) :sub (:sub claims) :subname (:subname claims)
                     :iss (:iss claims) :auth_level 0 :authGrantId (:authGrantId claims)
                     :auditTrackingId (:auditTrackingId claims) :expires_in (- (:exp claims) (jwt/now))}))))

(defn- userinfo [srv realm req]
  (let [claims (token-claims srv (or (web/bearer req) (web/form1 req "access_token")))]
    (if (and claims (some #{"openid"} (:scope claims)))
      (let [u (idm/read-obj (:idm srv) (str realm "_user") (:sub claims))]
        (web/json 200 (merge {:sub (:sub claims) :subname (:subname claims)} (user-claims u (:scope claims)))))
      (web/json 401 {:error "invalid_token" :error_description "The access token provided is expired, revoked, malformed, or invalid for other reasons."}))))

(defn- revoke [{:keys [tokens] :as srv} realm req]
  (let [{:keys [client error]} (authenticate-client srv realm req)
        tok (web/form1 req "token")
        entry (get @tokens tok)
        owner (or (get-in entry [:claims :client_id]) (get-in entry [:grant :client_id]))]
    (cond
      error error
      (and entry (not= owner (:id client))) (web/oauth-error 400 "unauthorized_client" "token belongs to another client")
      :else (do (when entry
                  (let [gid (or (get-in entry [:claims :authGrantId]) (:grant-id entry))]
                    (swap! tokens (fn [m] (into {} (remove (fn [[_ e]] (= gid (or (get-in e [:claims :authGrantId]) (:grant-id e)))) m))))))
                (web/json 200 {})))))

(defn- discovery [srv realm]
  (let [i (issuer srv realm)]
    {:issuer i :authorization_endpoint (str i "/authorize") :token_endpoint (str i "/access_token")
     :userinfo_endpoint (str i "/userinfo") :introspection_endpoint (str i "/introspect")
     :revocation_endpoint (str i "/token/revoke") :jwks_uri (str i "/connect/jwk_uri")
     :end_session_endpoint (str i "/connect/endSession")
     :response_types_supported ["code"] :subject_types_supported ["public"]
     :id_token_signing_alg_values_supported ["RS256"]
     :grant_types_supported ["client_credentials" "password" "authorization_code" "refresh_token"
                             "urn:ietf:params:oauth:grant-type:jwt-bearer"]
     :token_endpoint_auth_methods_supported ["client_secret_basic" "client_secret_post" "private_key_jwt" "none"]
     :code_challenge_methods_supported ["plain" "S256"]
     :scopes_supported (vec (sort (distinct (mapcat :scopes (vals (clients @(:tenant srv)))))))
     :claims_supported ["sub" "subname" "email" "given_name" "family_name" "name" "phone_number"]}))

(defn handle
  "Dispatch one request under /am/oauth2[/realms/root/realms/<realm>]/<rest>."
  [srv req realm rest]
  (case [(:method req) rest]
    ["GET" ".well-known/openid-configuration"] (web/json 200 (discovery srv realm))
    ["GET" "connect/jwk_uri"] (web/json 200 (jwt/jwks (:key srv)))
    ["POST" "access_token"] (token-endpoint srv realm req)
    ["POST" "introspect"] (introspect srv realm req)
    ["GET" "userinfo"] (userinfo srv realm req)
    ["POST" "userinfo"] (userinfo srv realm req)
    ["POST" "token/revoke"] (revoke srv realm req)
    ["GET" "authorize"] (authorize srv realm req)
    ["POST" "authorize"] (authorize srv realm req)
    ["GET" "connect/endSession"] (do (when-let [s (sso-session srv req)] (swap! (:sso srv) dissoc (:tokenId s)))
                                     (if-let [u (web/param req "post_logout_redirect_uri")] (web/redirect u) (web/json 200 {})))
    (web/error 404 (str "no OAuth2 endpoint " (:method req) " " rest))))
