(ns sling.image-test
  "The image `bb image` builds (localhost/sling:<VERSION>), run by the real Podman: it serves this repository's own
  Frodo fixture export from a mount at /tenant under the fixed public URL, and the tokens it mints verify against the JWKS
  it publishes. Nothing is mocked; without Podman or without the image the test says so and skips (`bb image` builds it)."
  (:require [cheshire.core :as json]
            [clojure.java.io :as io]
            [clojure.java.shell :refer [sh]]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [sling.jwt :as jwt])
  (:import (java.net ServerSocket URI)
           (java.net.http HttpClient HttpRequest HttpRequest$BodyPublishers HttpResponse$BodyHandlers)))

(def image (str "localhost/sling:" (str/trim (slurp "VERSION"))))
(def public-url "http://fakeping.localhost:8090")
(def issuer (str public-url "/am/oauth2/realms/root/realms/alpha"))

(defn- podman [& args] (apply sh "podman" args))

(defn- skip-reason []
  (try (cond (not (zero? (:exit (podman "info")))) "Podman does not answer"
             (not (zero? (:exit (podman "image" "exists" image)))) (str "image " image " is not built (bb image)"))
       (catch Exception e (str "no podman: " (.getMessage e)))))

(defn- free-port [] (with-open [s (ServerSocket. 0)] (.getLocalPort s)))
(defn- abspath [p] (.getAbsolutePath (io/file p)))
(def ^:private http (HttpClient/newHttpClient))

(defn- request [method url & {:keys [headers form]}]
  (let [b (HttpRequest/newBuilder (URI. url))
        b (reduce (fn [b [k v]] (.header b k v)) b headers)
        r (.send http (.build (.method b method (if form (HttpRequest$BodyPublishers/ofString form) (HttpRequest$BodyPublishers/noBody))))
                 (HttpResponse$BodyHandlers/ofString))]
    {:status (.statusCode r) :body (.body r)}))

(defn- wait-ready! [base]
  (loop [n 60]
    (let [ok (try (= 200 (:status (request "GET" (str base "/am/oauth2/realms/root/realms/alpha/.well-known/openid-configuration")))) (catch Exception _ false))]
      (cond ok true
            (zero? n) (throw (ex-info "the container did not answer" {:base base}))
            :else (do (Thread/sleep 500) (recur (dec n)))))))

(defn- with-container
  "Runs `f` with the base URL on the host of a container of the image started with `args` (after `podman run`'s image)
  and the mounts; the container is removed afterwards, whatever happens."
  [mounts args f]
  (let [name (str "sling-test-" (Long/toString (System/nanoTime) 36))
        port (free-port)
        run (apply podman "run" "-d" "--name" name "-p" (str "127.0.0.1:" port ":8090")
                   (concat (mapcat (fn [[from to]] ["-v" (str (abspath from) ":" to ":ro,z")]) mounts) [image] args))]
    (when-not (zero? (:exit run)) (throw (ex-info (str "podman run failed: " (:err run)) run)))
    (try (let [base (str "http://127.0.0.1:" port)] (wait-ready! base) (f base))
         (finally (podman "rm" "-f" name)))))

(deftest the-image-serves-a-frodo-export-from-a-mount
  (if-let [why (skip-reason)]
    (println "SKIPPED the-image-serves-a-frodo-export-from-a-mount:" why)
    (do
      (testing "the defaults: the export at /tenant, the fixed public URL, nothing baked in"
        (with-container {"test/fixtures/frodo-export" "/tenant"} []
          (fn [base]
            (let [d (json/parse-string (:body (request "GET" (str base "/am/oauth2/realms/root/realms/alpha/.well-known/openid-configuration"))) true)]
              (is (= issuer (:issuer d)) "the issuer is the fixed public URL, whatever address it was asked on")
              (is (= (str issuer "/connect/jwk_uri") (:jwks_uri d)))))))
      (testing "tokens verify against the published JWKS (client secrets come from a second mount, the CLI flags as they are)"
        (with-container {"test/fixtures/frodo-export" "/tenant" "test/fixtures/frodo-services.edn" "/services.edn"}
          ["--frodo" "/tenant" "--services" "/services.edn" "--bind" "0.0.0.0" "--port" "8090" "--public-url" public-url]
          (fn [base]
            (let [basic (str "Basic " (.encodeToString (java.util.Base64/getEncoder) (.getBytes "orders-service:orders-secret")))
                  t (request "POST" (str base "/am/oauth2/realms/root/realms/alpha/access_token")
                             :headers {"Authorization" basic "Content-Type" "application/x-www-form-urlencoded"}
                             :form "grant_type=client_credentials&scope=fr%3Aidm%3A*")
                  token (:access_token (json/parse-string (:body t) true))
                  jwks (json/parse-string (:body (request "GET" (str base "/am/oauth2/realms/root/realms/alpha/connect/jwk_uri"))) true)]
              (is (= 200 (:status t)))
              (is (:ok (jwt/verify token jwks :iss issuer)) "signed by the key the container publishes, iss is the public URL")
              (is (= "bad signature" (:error (jwt/verify (str token "x") jwks))) "a tampered token is refused"))))))))
