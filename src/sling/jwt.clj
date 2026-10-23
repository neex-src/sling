(ns sling.jwt
  "RS256 JSON Web Tokens with the JDK alone: one RSA key per server, its JWK set, signing, and
  checking a token against a JWK set (ours, a client's or a service account's).

  A key is {:kid s :private PrivateKey :public RSAPublicKey}. Verification answers
  {:ok claims} or {:error why}; it never throws on bad input."
  (:require [cheshire.core :as json]
            [clojure.string :as str])
  (:import (java.math BigInteger)
           (java.security KeyFactory KeyPairGenerator Signature)
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

(defn- jwk->public [{:keys [n e]}]
  (.generatePublic (KeyFactory/getInstance "RSA")
                   (RSAPublicKeySpec. (BigInteger. 1 (unb64url n)) (BigInteger. 1 (unb64url e)))))

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
  "Check signature (RS256 against `jwk-set`, picked by kid when the token names one) and exp/nbf.
  Optional :aud and :iss must then match."
  [token jwk-set & {:keys [aud iss]}]
  (if-let [{:keys [header claims input sig]} (decode token)]
    (let [ks (:keys jwk-set)
          k (or (first (filter #(= (:kid %) (:kid header)) ks)) (when (nil? (:kid header)) (first ks)))
          auds (let [a (:aud claims)] (set (if (sequential? a) a [a])))]
      (cond
        (not= "RS256" (:alg header)) {:error (str "alg " (:alg header) " not accepted, only RS256")}
        (nil? k) {:error (str "no key with kid " (pr-str (:kid header)))}
        (not (try (.verify (doto (Signature/getInstance "SHA256withRSA")
                             (.initVerify (jwk->public k))
                             (.update (.getBytes ^String input "UTF-8")))
                           (unb64url sig))
                  (catch Exception _ false)))
        {:error "bad signature"}
        (and (:exp claims) (< (:exp claims) (now))) {:error "expired"}
        (and (:nbf claims) (> (:nbf claims) (+ (now) 5))) {:error "not yet valid"}
        (and aud (not (some auds (if (coll? aud) aud [aud])))) {:error (str "aud " (pr-str (:aud claims)) " is not " (pr-str aud))}
        (and iss (not= iss (:iss claims))) {:error (str "iss " (pr-str (:iss claims)) " is not " (pr-str iss))}
        :else {:ok claims}))
    {:error "not a JWT"}))
