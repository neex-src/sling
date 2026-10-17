(ns login
  "A client for /authenticate: answers each callback from the options and prints every step,
  which is the 'customer request' half of the demo. NameCallback gets --user, PasswordCallback
  --password, TextInputCallback --otp."
  (:require [babashka.cli :as cli]
            [babashka.http-client :as http]
            [cheshire.core :as json]
            [clojure.string :as str]))

(def opts (cli/parse-opts *command-line-args* {:require [:base :user :password]}))
(def url (str (str/replace (:base opts) #"/+$" "") "/am/json/realms/root/realms/alpha/authenticate"
              (when-let [j (:journey opts)] (str "?authIndexType=service&authIndexValue=" j))))
(def headers (cond-> {"Content-Type" "application/json" "X-Sling-Debug" "true"}
               (:ip opts) (assoc "X-Forwarded-For" (:ip opts))))

(defn post [body]
  (let [r (http/post url {:headers headers :body (when body (json/generate-string body)) :throw false})]
    {:status (:status r) :body (json/parse-string (:body r) true)}))

(defn fill [cb]
  (if-let [in (first (:input cb))]
    (let [v (case (:type cb)
              "NameCallback" (:user opts)
              "PasswordCallback" (:password opts)
              "TextInputCallback" (str (:otp opts))
              (:value in))]
      (println "  asked:" (:type cb) (pr-str (:value (first (:output cb)))) "-> answering" (if (= "PasswordCallback" (:type cb)) "***" (pr-str v)))
      (assoc-in cb [:input 0 :value] v))
    cb))

(loop [r (post nil)]
  (if-let [cbs (get-in r [:body :callbacks])]
    (recur (post {:authId (get-in r [:body :authId]) :callbacks (mapv fill cbs)}))
    (do (println (:status r) (json/generate-string (dissoc (:body r) :_sling)))
        (when-let [d (get-in r [:body :_sling])]
          (println "  path:" (str/join " -> " (map #(str (:node %) (when (:outcome %) (str " [" (:outcome %) "]"))) (:trace d))))
          (when (:reason d) (println "  why: " (:reason d)))
          (when (seq (:sessionProperties d)) (println "  session properties:" (json/generate-string (:sessionProperties d))))))))
