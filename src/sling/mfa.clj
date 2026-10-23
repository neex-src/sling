(ns sling.mfa
  "Second factors and suspended journeys, from the node reference:

    OneTimePasswordGeneratorNode  OneTimePasswordSmtpSenderNode  OneTimePasswordSmsSenderNode
    OneTimePasswordCollectorDecisionNode  OathRegistrationNode  OathTokenVerifierNode  EmailSuspendNode

  Nothing leaves the machine: mail and SMS land in the outbox (GET /sling/outbox), with the
  code or the resume link. OATH is real TOTP/HOTP (RFC 6238/4226), so an authenticator app works;
  a test can compute the code itself with `totp`, or read the secret from the outbox.

  Assumed where the docs are silent: the generated OTP lives in transient `oneTimePassword` with
  shared `oneTimePasswordTimestamp`; OATH devices are kept on the user under
  _meta/oathDeviceProfiles; resume links are <public-url>/am/XUI/?realm=/<r>&suspendedId=<id>."
  (:require [clojure.string :as str]
            [sling.engine :as engine]
            [sling.idm :as idm]
            [sling.jwt :as jwt]
            [sling.outside :as outside])
  (:import (java.nio ByteBuffer)
           (java.security SecureRandom)
           (javax.crypto Mac)
           (javax.crypto.spec SecretKeySpec)))

(def ^:private rng (SecureRandom.))

;; ---- OATH ----------------------------------------------------------------------------------

(def ^:private b32 "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

(defn base32 [^bytes bs]
  (let [bits (apply str (map #(let [s (Integer/toBinaryString (bit-and % 0xff))] (str (subs "00000000" (count s)) s)) bs))
        padded (str bits (subs "00000" 0 (mod (- 5 (mod (count bits) 5)) 5)))]
    (apply str (map #(nth b32 (Integer/parseInt (apply str %) 2)) (partition 5 padded)))))

(defn- hex->bytes [h] (byte-array (map #(unchecked-byte (Integer/parseInt (apply str %) 16)) (partition 2 h))))
(defn- bytes->hex [bs] (apply str (map #(format "%02x" (bit-and % 0xff)) bs)))

(defn hotp
  "RFC 4226 code for `secret-hex` at `counter`."
  [secret-hex counter digits alg]
  (let [mac (doto (Mac/getInstance alg) (.init (SecretKeySpec. (hex->bytes secret-hex) alg)))
        h (.doFinal mac (.array (.putLong (ByteBuffer/allocate 8) counter)))
        o (bit-and (aget h (dec (count h))) 0xf)
        bin (bit-or (bit-shift-left (bit-and (aget h o) 0x7f) 24) (bit-shift-left (bit-and (aget h (+ o 1)) 0xff) 16)
                    (bit-shift-left (bit-and (aget h (+ o 2)) 0xff) 8) (bit-and (aget h (+ o 3)) 0xff))
        code (str (mod bin (long (Math/pow 10 digits))))]
    (str (apply str (repeat (- digits (count code)) "0")) code)))

(defn- mac-alg [cfg] (case (:totpHashAlgorithm cfg) "HMAC_SHA256" "HmacSHA256" "HMAC_SHA512" "HmacSHA512" "HmacSHA1"))
(defn- digits [cfg] (case (str (:passwordLength cfg)) "EIGHT_DIGITS" 8 6))

(defn totp
  "The TOTP code for `secret-hex` now (or `step-offset` steps away)."
  ([secret-hex] (totp secret-hex {} 0))
  ([secret-hex cfg step-offset]
   (hotp secret-hex (+ (quot (jwt/now) (or (:totpTimeInterval cfg) 30)) step-offset) (digits cfg) (mac-alg cfg))))

(defn- users-of [tenant session]
  (let [r (get-in tenant [:trees (:journey session) :identityResource])]
    (if r (str/replace r #"^managed/" "") (str (get-in tenant [:services :realm] "alpha") "_user"))))

(defn- current-user [tenant session]
  (let [store (get-in tenant [:services :idm]) type (users-of tenant session)]
    (when store
      (or (some->> (get-in session [:shared "_id"]) (idm/read-obj store type))
          (some->> (get-in session [:shared "username"]) (idm/find-by store type :userName))))))

(defn- save-device! [tenant session user device]
  (idm/patch! (get-in tenant [:services :idm]) (users-of tenant session) (:_id user)
              [{:operation "replace" :field "/_meta/oathDeviceProfiles"
                :value (conj (vec (get-in user [:_meta :oathDeviceProfiles])) device)}]))

(defmethod engine/run-node "OathRegistrationNode" [{:keys [tenant session config inputs]}]
  (let [u (current-user tenant session)]
    (cond
      (nil? u) {:outcome "failureOutcome"}
      (seq inputs) (do (save-device! tenant session u (get-in session [:shared "sling.oathPending"]))
                       {:outcome "successOutcome" :shared {"sling.oathPending" nil}})
      :else
      (let [secret (bytes->hex (let [b (byte-array (max 20 (quot (or (:minSharedSecretLength config) 32) 2)))] (.nextBytes rng b) b))
            label (if (= "EMAIL_ADDRESS" (:accountName config)) (:mail u) (:userName u))
            uri (str "otpauth://totp/" (or (:issuer config) "ForgeRock") ":" label
                     "?secret=" (base32 (hex->bytes secret)) "&issuer=" (or (:issuer config) "ForgeRock")
                     "&digits=" (digits config) "&period=" (or (:totpTimeInterval config) 30))
            device {:uuid (str (random-uuid)) :deviceName "OATH Device" :sharedSecret secret :algorithm (or (:algorithm config) "TOTP")}]
        (outside/send-mail! (:services tenant) {:kind "oath-registration" :to (:userName u) :uri uri :secret secret})
        {:shared {"sling.oathPending" device}
         :callbacks [{:type "TextOutputCallback" :args {:messageType 0 :message "Scan the QR code image below with the ForgeRock Authenticator app to register your device with your login."}}
                     {:type "HiddenValueCallback" :args {:id "mfaDeviceRegistration" :value uri}}
                     {:type "ConfirmationCallback" :args {:prompt "" :options ["Next"]}}]}))))

(defmethod engine/run-node "OathTokenVerifierNode" [{:keys [tenant session config inputs]}]
  (let [u (current-user tenant session)
        devices (get-in u [:_meta :oathDeviceProfiles])]
    (cond
      (empty? devices) {:outcome "notRegisteredOutcome" :shared {"mfaMethod" "oath"}}
      (seq inputs)
      (let [code (str (:value (first inputs)))
            steps (or (:totpTimeSteps config) 2)
            ok? (some (fn [d] (some #(= code (totp (:sharedSecret d) config %)) (range (- steps) (inc steps)))) devices)]
        {:outcome (if ok? "successOutcome" "failureOutcome")})
      :else {:callbacks [{:type "NameCallback" :args {:prompt "Enter verification code"}}]})))

;; ---- one-time passwords by mail and SMS ----------------------------------------------------

(defmethod engine/run-node "OneTimePasswordGeneratorNode" [{:keys [config]}]
  (let [n (or (:length config) 8)
        code (apply str (repeatedly n #(.nextInt rng 10)))]
    {:outcome "outcome" :transient {"oneTimePassword" code} :shared {"oneTimePasswordTimestamp" (jwt/now)}}))

(defn- localized [m] (if (map? m) (or (:en m) (first (vals m))) m))

(defn- send-otp [kind addr-attr default-attr {:keys [tenant session config]}]
  (let [u (current-user tenant session)
        to (or (get u (keyword (or (get config addr-attr) default-attr))) (get-in session [:shared "objectAttributes" (keyword default-attr)]))
        code (get-in session [:transient "oneTimePassword"])]
    (if (and to code)
      (do (outside/send-mail! (:services tenant)
                              {:kind kind :to to :subject (localized (:emailSubject config)) :otp code
                               :body (str/replace (or (localized (:emailContent config)) "Your one-time password: {{OTP}}") "{{OTP}}" code)})
          {:outcome "outcome"})
      {:error (str "no " (if (= kind "sms") "phone number" "mail address") " or no generated password to send")})))

(defmethod engine/run-node "OneTimePasswordSmtpSenderNode" [ctx] (send-otp "email" :emailAttribute "mail" ctx))
(defmethod engine/run-node "OneTimePasswordSmsSenderNode" [ctx] (send-otp "sms" :mobilePhoneAttributeName "telephoneNumber" ctx))

(defmethod engine/run-node "OneTimePasswordCollectorDecisionNode" [{:keys [config session inputs]}]
  (if (seq inputs)
    (let [fresh? (< (- (jwt/now) (or (get-in session [:shared "oneTimePasswordTimestamp"]) 0)) (* 60 (or (:passwordExpiryTime config) 5)))]
      {:outcome (if (and fresh? (= (str (:value (first inputs))) (get-in session [:transient "oneTimePassword"]))) "true" "false")})
    {:callbacks [{:type "PasswordCallback" :args {:prompt "One Time Password"}}]}))

;; ---- Email Suspend -------------------------------------------------------------------------

(defn- render [tpl obj]
  (str/replace (or tpl "") #"\{\{\s*object\.([\w.]+)\s*\}\}" (fn [[_ k]] (str (get-in obj (map keyword (str/split k #"\.")))))))

(defmethod engine/run-node "EmailSuspendNode" [{:keys [tenant session config]}]
  (if (:resumed session)
    {:outcome "outcome"}
    (let [u (when (:objectLookup config) (current-user tenant session))
          attr (keyword (or (:emailAttribute config) "mail"))
          to (or (get u attr) (get-in session [:shared "objectAttributes" attr]) (get-in session [:shared (name attr)]))
          id (str/replace (str (random-uuid)) "-" "")
          realm (get-in tenant [:services :realm] "alpha")
          uri (str (get-in tenant [:services :public-url]) "/am/XUI/?realm=/" realm "&suspendedId=" id)
          tpl (get-in tenant [:email-templates (:emailTemplateName config)])
          obj (merge (get-in session [:shared "objectAttributes"]) u {:resumeURI uri})]
      (if-not to
        {:error (str "no " (name attr) " to send the " (:emailTemplateName config) " mail to")}
        (do (outside/send-mail! (:services tenant) {:kind "email" :to to :template (:emailTemplateName config)
                                                    :subject (localized (:subject tpl)) :resumeURI uri
                                                    :body (render (localized (:message tpl)) obj)})
            {:suspend {:id id :message (localized (:emailSuspendMessage config))}})))))
