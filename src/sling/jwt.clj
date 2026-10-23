(ns sling.jwt
  "JSON Web Tokens with the JDK alone: one RSA key per server, its JWK set, RS256 signing, and
  checking a token (RS*, PS256, ES*) against a JWK set: ours, a client's, a service account's or a
  trusted issuer's.

  A key is {:kid s :private PrivateKey :public RSAPublicKey}. Verification answers
  {:ok claims} or {:error why}; it never throws on bad input."
  (:require [cheshire.core :as json]
            [clojure.string :as str])
  (:import (java.math BigInteger)
           (java.security AlgorithmParameters KeyFactory KeyPairGenerator Signature)
           (java.security.spec ECGenParameterSpec ECParameterSpec ECPoint ECPublicKeySpec MGF1ParameterSpec PSSParameterSpec)
           (java.security.interfaces RSAPublicKey)
           (java.security.spec RSAPublicKeySpec)
           (java.util Base64 UUID)))

(defn b64url [^bytes bs] (.encodeToString (.withoutPadding (Base64/getUrlEncoder)) bs))
(defn unb64url ^bytes [^String s] (.decode (Base64/getUrlDecoder) s))

(defn- uint-bytes
  "Big-endian magnitude without the sign byte, as JWK wants n and e."
  [^BigInteger n]
  (let [bs (.toByteArray n)]
    (if (and (> (count bs) 1) (zero? (aget bs 0))) (java.util.Arrays/copyOfRange bs 1 (count bs)) bs)))

(defn new-key
  "A fresh 2048-bit RSA key. `kid` defaults to a random one."
  ([] (new-key (str (UUID/randomUUID))))
  ([kid]
   (let [g (doto (KeyPairGenerator/getInstance "RSA") (.initialize 2048))
         kp (.generateKeyPair g)]
     {:kid kid :private (.getPrivate kp) :public (.getPublic kp)})))

(defn public-jwk [{:keys [kid ^RSAPublicKey public]}]
  {:kty "RSA" :kid kid :use "sig" :alg "RS256"
   :n (b64url (uint-bytes (.getModulus public)))
   :e (b64url (uint-bytes (.getPublicExponent public)))})

(defn jwks [& keys] {:keys (mapv public-jwk keys)})

(defn- jwk->public [{:keys [kty n e crv x y]}]
  (if (= "EC" kty)
    (let [params (.getParameterSpec (doto (AlgorithmParameters/getInstance "EC")
                                      (.init (ECGenParameterSpec. (case crv "P-384" "secp384r1" "P-521" "secp521r1" "secp256r1"))))
                                    ECParameterSpec)]
      (.generatePublic (KeyFactory/getInstance "EC")
                       (ECPublicKeySpec. (ECPoint. (BigInteger. 1 (unb64url x)) (BigInteger. 1 (unb64url y))) params)))
    (.generatePublic (KeyFactory/getInstance "RSA")
                     (RSAPublicKeySpec. (BigInteger. 1 (unb64url n)) (BigInteger. 1 (unb64url e))))))

(def ^:private algs
  {"RS256" "SHA256withRSA" "RS384" "SHA384withRSA" "RS512" "SHA512withRSA"
   "PS256" "RSASSA-PSS" "ES256" "SHA256withECDSA" "ES384" "SHA384withECDSA" "ES512" "SHA512withECDSA"})

(defn- der
  "A JWS ECDSA signature (R||S) as the DER sequence the JDK verifies."
  [^bytes raw]
  (let [half (quot (count raw) 2)
        int-der (fn [bs] (let [v (.toByteArray (BigInteger. 1 bs))] (byte-array (concat [2 (count v)] v))))
        r (int-der (java.util.Arrays/copyOfRange raw 0 half))
        s (int-der (java.util.Arrays/copyOfRange raw half (count raw)))
        body (byte-array (concat r s))
        len (count body)]
    (byte-array (concat [0x30] (if (< len 128) [len] [0x81 len]) body))))

(defn- sig-ok? [alg k ^String input ^bytes sig]
  (let [sg (doto (Signature/getInstance (algs alg))
             (cond-> (= alg "PS256") (.setParameter (PSSParameterSpec. "SHA-256" "MGF1" MGF1ParameterSpec/SHA256 32 1))))]
    (.initVerify sg (jwk->public k))
    (.update sg (.getBytes input "UTF-8"))
    (.verify sg (if (str/starts-with? alg "ES") (der sig) sig))))

(defn sign
  "Compact JWS of `claims` with `key`. `header` adds to {alg typ kid}."
  ([key claims] (sign key claims {}))
  ([{:keys [kid private]} claims header]
   (let [h (b64url (.getBytes (json/generate-string (merge {:typ "JWT" :alg "RS256" :kid kid} header)) "UTF-8"))
         p (b64url (.getBytes (json/generate-string claims) "UTF-8"))
         input (str h "." p)
         sig (doto (Signature/getInstance "SHA256withRSA") (.initSign private) (.update (.getBytes input "UTF-8")))]
     (str input "." (b64url (.sign sig))))))

(defn decode
  "Header and claims of a compact JWT without checking anything, or nil if it is not one."
  [token]
  (let [parts (str/split (str token) #"\.")]
    (when (= 3 (count parts))
      (try {:header (json/parse-string (String. (unb64url (parts 0)) "UTF-8") true)
            :claims (json/parse-string (String. (unb64url (parts 1)) "UTF-8") true)
            :input (str (parts 0) "." (parts 1))
            :sig (parts 2)}
           (catch Exception _ nil)))))

(defn now [] (quot (System/currentTimeMillis) 1000))

(defn verify
  "Check signature (RS*/PS256/ES* against `jwk-set`, picked by kid when the token names one) and exp/nbf.
  Optional :aud and :iss must then match."
  [token jwk-set & {:keys [aud iss]}]
  (if-let [{:keys [header claims input sig]} (decode token)]
    (let [ks (:keys jwk-set)
          k (or (first (filter #(= (:kid %) (:kid header)) ks)) (when (nil? (:kid header)) (first ks)))
          auds (let [a (:aud claims)] (set (if (sequential? a) a [a])))]
      (cond
        (not (algs (:alg header))) {:error (str "alg " (:alg header) " not accepted")}
        (nil? k) {:error (str "no key with kid " (pr-str (:kid header)))}
        (not (try (sig-ok? (:alg header) k input (unb64url sig)) (catch Exception _ false)))
        {:error "bad signature"}
        (and (:exp claims) (< (:exp claims) (now))) {:error "expired"}
        (and (:nbf claims) (> (:nbf claims) (+ (now) 5))) {:error "not yet valid"}
        (and aud (not (some auds (if (coll? aud) aud [aud])))) {:error (str "aud " (pr-str (:aud claims)) " is not " (pr-str aud))}
        (and iss (not= iss (:iss claims))) {:error (str "iss " (pr-str (:iss claims)) " is not " (pr-str iss))}
        :else {:ok claims}))
    {:error "not a JWT"}))
