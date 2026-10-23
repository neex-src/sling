(ns sling.web
  "Requests and answers as plain maps, so every part of the fake tenant is a function from one to
  the other and a test can call it without a socket.

    request  {:method \"GET\" :path \"/am/...\" :query {name [v]} :headers {lower-name [v]} :body string}
    response {:status n :headers {name v} :body string-or-data}   data goes out as JSON

  Error bodies have the shape the platform's REST layer uses: {:code :reason :message}."
  (:require [cheshire.core :as json]
            [clojure.string :as str])
  (:import (java.net URLDecoder URLEncoder)
           (java.util Base64)))

(defn decode-form [s]
  (reduce (fn [m kv]
            (let [[k v] (str/split kv #"=" 2)]
              (update m (URLDecoder/decode ^String k "UTF-8") (fnil conj [])
                      (URLDecoder/decode ^String (or v "") "UTF-8"))))
          {} (remove str/blank? (str/split (or s "") #"&"))))

(defn url-encode [s] (str/replace (URLEncoder/encode (str s) "UTF-8") "+" "%20"))

(defn query-string [m]
  (str/join "&" (for [[k v] m :when (some? v)] (str (url-encode (name k)) "=" (url-encode v)))))

(defn header [req k] (first (get-in req [:headers (str/lower-case k)])))
(defn param [req k] (first (get-in req [:query k])))

(defn json-body [req]
  (when-not (str/blank? (:body req)) (json/parse-string (:body req) true)))

(defn form
  "Form fields of a POST body, falling back to the query string, as OAuth endpoints accept both."
  [req]
  (merge (:query req)
         (when (str/includes? (or (header req "content-type") "") "x-www-form-urlencoded")
           (decode-form (:body req)))))

(defn form1 [req k] (first (get (form req) k)))

(defn cookies [req]
  (into {} (for [h (get-in req [:headers "cookie"])
                 kv (str/split h #";\s*")
                 :let [[k v] (str/split kv #"=" 2)]
                 :when v]
             [(str/trim k) v])))

(defn bearer [req]
  (some->> (header req "authorization") (re-matches #"(?i)bearer\s+(.+)") second))

(defn basic
  "[id secret] from an Authorization: Basic header, or nil."
  [req]
  (when-let [[_ b] (some->> (header req "authorization") (re-matches #"(?i)basic\s+(.+)"))]
    (let [[id secret] (str/split (String. (.decode (Base64/getDecoder) ^String b) "UTF-8") #":" 2)]
      [(URLDecoder/decode id "UTF-8") (URLDecoder/decode (or secret "") "UTF-8")])))

(defn json [status data] {:status status :headers {"Content-Type" "application/json"} :body data})

(def reasons {400 "Bad Request" 401 "Unauthorized" 403 "Forbidden" 404 "Not Found" 405 "Method Not Allowed"
              409 "Conflict" 412 "Precondition Failed" 500 "Internal Server Error" 501 "Not Implemented"})

(defn error [status message] (json status {:code status :reason (reasons status "Error") :message message}))

(defn oauth-error
  "RFC 6749 error body, which the OAuth2 endpoints use instead of the REST shape."
  [status code description]
  (json status {:error code :error_description description}))

(defn redirect [location & {:keys [cookies]}]
  {:status 302 :headers (cond-> {"Location" location}
                          (seq cookies) (assoc "Set-Cookie" (vec cookies)))
   :body ""})

(defn html [body] {:status 200 :headers {"Content-Type" "text/html; charset=utf-8"} :body body})
