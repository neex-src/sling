(ns sling.idmscript
  "Runs one IDM script (a custom endpoint, a managed object trigger, a mapping transform) in
  GraalJS with the IDM bindings of resources/sling/idm-bindings.js.

  `dispatch` answers every openidm.* call: (dispatch op args) with op one of create read update
  patch delete query action property hash matches uuid, args as the script passed them. It returns
  a Clojure value, or throws ex-info with {:code n} which the script sees as a thrown {code, message}.

  Returns {:value v :object o :logs [] :error nil} or {:error {:code n :message s}}."
  (:require [cheshire.core :as json]
            [clojure.java.io :as io])
  (:import (org.graalvm.polyglot Context Engine PolyglotException Source Value)
           (org.graalvm.polyglot.proxy ProxyExecutable)))

(def ^:private engine
  (delay (-> (Engine/newBuilder (into-array String ["js"]))
             (.option "engine.WarnInterpreterOnly" "false")
             (.build))))

(def ^:private prelude (delay (slurp (io/resource "sling/idm-bindings.js"))))

(defn- thrown
  "The {code message} an IDM script threw, from the guest object or the message."
  [^PolyglotException e]
  (let [g (when (.isGuestException e) (.getGuestObject e))
        member #(when (and g (.hasMember g %)) (let [v (.getMember g %)] (when-not (.isNull v) v)))]
    {:code (or (some-> (member "code") .asInt) 500)
     :message (or (some-> (member "message") .asString) (.getMessage e))}))

(defn run
  "Run `source` with `vars` (a map turned into globals: request, context, object ...)."
  [source vars dispatch]
  (let [host (reify ProxyExecutable
               (execute [_ args]
                 (let [op (.asString ^Value (aget args 0))
                       a (json/parse-string (.asString ^Value (aget args 1)) true)]
                   (json/generate-string
                    (try (dispatch op a)
                         (catch clojure.lang.ExceptionInfo e
                           {:__error {:code (or (:code (ex-data e)) 500) :message (ex-message e)}}))))))]
    (with-open [ctx (-> (Context/newBuilder (into-array String ["js"])) (.engine @engine) (.build))]
      (try
        (let [env (.execute (.eval ctx (Source/create "js" ^String @prelude)) (object-array [host (json/generate-string vars)]))
              globals (.getBindings ctx "js")
              bindings (.getMember env "bindings")]
          (doseq [k (.getMemberKeys bindings)] (.putMember globals k (.getMember bindings k)))
          (let [v (.eval ctx (Source/create "js" ^String source))]
            (assoc (json/parse-string (.asString (.execute (.getMember env "result") (object-array [v]))) true) :error nil)))
        (catch PolyglotException e {:error (thrown e)})))))
