(ns sling.outside
  "Everything the tenant does to the world outside it: HTTP calls (journey httpClient, IDM
  external/rest) and mail (OTP senders, Email Suspend, IDM external/email).

  HTTP answers, in order: the first matching fake in services :http, else a real call when the URL
  starts with one of services :passthrough (e.g. \"http://localhost:\"), so a journey or an
  endpoint can call the service you are running locally; anything else answers 599, loudly.

  Mail goes to the outbox, services :outbox (an atom of a vector), which the server shows at
  GET /sling/outbox: that is where you read the code or the resume link."
  (:require [cheshire.core :as json]
            [clojure.string :as str])
  (:import (java.net URI)
           (java.net.http HttpClient HttpRequest HttpRequest$BodyPublishers HttpResponse$BodyHandlers)
           (java.time Duration Instant)))

(defn- match? [m uri]
  (if (str/ends-with? m "*") (str/starts-with? uri (subs m 0 (dec (count m)))) (= m uri)))

(def ^:private client (delay (HttpClient/newBuilder)))

(defn- real-call [{:keys [uri method headers body]}]
  (try
    (let [b (reduce (fn [b [k v]] (.header b (name k) (str v)))
                    (-> (HttpRequest/newBuilder (URI. uri)) (.timeout (Duration/ofSeconds 30)))
                    (remove (fn [[k]] (#{"host" "content-length" "connection"} (str/lower-case (name k)))) headers))
          r (.send (.build @client)
                   (.build (.method b method (if body (HttpRequest$BodyPublishers/ofString body) (HttpRequest$BodyPublishers/noBody))))
                   (HttpResponse$BodyHandlers/ofString))]
      {:status (.statusCode r) :headers (into {} (for [[k vs] (.map (.headers r))] [k (first vs)])) :body (.body r)})
    (catch Exception e
      {:status 599 :statusText "sling: passthrough failed" :headers {} :body (str "passthrough to " uri " failed: " e)})))

(defn http
  "One outgoing call {:uri :method :headers {} :body string-or-nil} -> {:status :headers :body string}."
  [{:keys [http passthrough]} {:keys [uri method] :as req}]
  (let [method (str/upper-case (or method "GET"))
        hit (first (filter #(and (match? (:match %) uri)
                                 (or (nil? (:method %)) (= method (str/upper-case (:method %)))))
                           http))]
    (cond
      hit (let [{:keys [status body headers]} (:response hit)]
            {:status (or status 200) :headers (or headers {})
             :body (if (string? body) body (json/generate-string body))})
      (some #(str/starts-with? uri %) passthrough) (real-call (assoc req :method method))
      :else {:status 599 :statusText "sling: no fake registered" :headers {}
             :body (str "no fake for " method " " uri)})))

(defn send-mail!
  "Put a message in the outbox. msg: {:to :subject :body :kind} plus anything worth showing."
  [{:keys [outbox]} msg]
  (when outbox (swap! outbox conj (assoc msg :at (str (Instant/now)))))
  msg)
