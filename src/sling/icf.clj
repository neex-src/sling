(ns sling.icf
  "system/<connector>/<objectType> through a real connector: the open-source OpenICF framework
  (OpenIdentityPlatform, CDDL, Maven Central) runs the Groovy scripted connector in-process, so the
  same Create/Search/Update/Delete scripts an RCS would run go against a real database.

  Needs the :icf alias. A connector is configured from the export's provisioner.openicf/<name>
  (connectorRef + configurationProperties + objectTypes) with :connectors <name> from services.edn
  on top, which is where local paths, URLs and passwords go:

    :connectors {\"HRDB\" {:scriptRoots [\"test/fixtures/connectors/hrdb\"]
                         :url \"jdbc:postgresql://127.0.0.1:15432/hr\" :username \"hr\" :password \"hr\"
                         :driverClassName \"org.postgresql.Driver\"}}

  Objects keep IDM's shape: _id is the ICF uid, other keys are the provisioner's property names
  (their nativeName is the ICF attribute), __NAME__ stays __NAME__ unless a property maps it."
  (:require [clojure.string :as str]
            [sling.idm :as idm])
  (:import (java.beans Introspector)
           (org.identityconnectors.common.security GuardedString)
           (org.identityconnectors.framework.api ConnectorFacadeFactory)
           (org.identityconnectors.framework.common.objects AttributeBuilder ConnectorObject Name ObjectClass
                                                            OperationOptionsBuilder ResultsHandler Uid)
           (org.identityconnectors.framework.common.objects.filter FilterBuilder)
           (org.identityconnectors.test.common TestHelpers)))

(def ^:private connectors
  {"ScriptedSQLConnector" ["org.forgerock.openicf.connectors.scriptedsql.ScriptedSQLConnector"
                           "org.forgerock.openicf.connectors.scriptedsql.ScriptedSQLConfiguration"]
   "ScriptedRESTConnector" ["org.forgerock.openicf.connectors.scriptedrest.ScriptedRESTConnector"
                            "org.forgerock.openicf.connectors.scriptedrest.ScriptedRESTConfiguration"]
   "ScriptedConnector" ["org.forgerock.openicf.connectors.groovy.ScriptedConnector"
                        "org.forgerock.openicf.connectors.groovy.ScriptedConfiguration"]})

(defn- coerce [^Class t v]
  (cond
    (nil? v) nil
    (= t GuardedString) (GuardedString. (.toCharArray (str v)))
    (.isArray t) (into-array (.getComponentType t) (map #(coerce (.getComponentType t) %) (if (sequential? v) v [v])))
    (#{Integer/TYPE Integer} t) (int v)
    (#{Long/TYPE Long} t) (long v)
    (#{Boolean/TYPE Boolean} t) (boolean v)
    (= t java.net.URI) (java.net.URI. (str v))
    :else v))

(defn- configure [cfg-class props]
  (let [cfg (.newInstance (Class/forName cfg-class))
        setters (into {} (for [pd (.getPropertyDescriptors (Introspector/getBeanInfo (class cfg)))
                               :when (.getWriteMethod pd)]
                           [(.getName pd) (.getWriteMethod pd)]))]
    (doseq [[k v] props
            :let [m (setters (name k))]
            :when (and m (some? v) (not (map? v)))]  ; {$crypto ..} / {$bool ..} blobs need the local value
      (.invoke m cfg (object-array [(coerce (first (.getParameterTypes m)) v)])))
    cfg))

(defn connect
  "A facade for one connector: provisioner (from the export, may be nil) plus local overrides."
  [provisioner local]
  (let [cname (last (str/split (or (get-in provisioner [:connectorRef :connectorName]) (:connectorName local)
                                   "ScriptedSQLConnector") #"\."))
        [conn-class cfg-class] (or (connectors cname) (throw (ex-info (str "connector " cname " is not one sling runs") {})))
        props (merge (:configurationProperties provisioner) (dissoc local :connectorName))
        api (TestHelpers/createTestConfiguration (Class/forName conn-class) (configure cfg-class props))]
    {:facade (.newInstance (ConnectorFacadeFactory/getInstance) api)
     :object-types (:objectTypes provisioner)}))

;; ---- IDM objects <-> ICF ------------------------------------------------------------------

(defn- object-class [{:keys [object-types]} type]
  (let [native (or (get-in object-types [(keyword type) :nativeType]) type)]
    (case native "__ACCOUNT__" ObjectClass/ACCOUNT "__GROUP__" ObjectClass/GROUP "account" ObjectClass/ACCOUNT (ObjectClass. native))))

(defn- native-names [{:keys [object-types]} type]
  (into {} (for [[k p] (get-in object-types [(keyword type) :properties]) :when (:nativeName p)] [k (:nativeName p)])))

(defn- ->attributes [c type obj]
  (let [names (native-names c type)]
    (set (for [[k v] (dissoc obj :_id :_rev)
               :let [n (get names k (name k))]]
           (if (= n "__NAME__")
             (Name. (str v))
             (AttributeBuilder/build ^String n ^java.util.Collection (if (sequential? v) (vec v) (if (nil? v) [] [v]))))))))

(defn- ->object [c type ^ConnectorObject co]
  (let [idm-name (into {} (map (fn [[k n]] [n k]) (native-names c type)))]
    (reduce (fn [m a]
              (let [n (.getName a)
                    vs (vec (.getValue a))]
                (if (= n "__UID__")
                  m
                  (assoc m (get idm-name n (keyword n)) (if (<= (count vs) 1) (first vs) vs)))))
            {:_id (.getUidValue (.getUid co))}
            (.getAttributes co))))

(defn- ->filter
  "An IDM query filter tree (sling.idm/parse-filter) as an ICF Filter; nil = everything."
  [c type expr]
  (let [names (native-names c type)
        attr (fn [p v] (let [k (first p) n (get names k (name k))]
                         (cond (= n "_id") (Uid. (str v)) (= n "__NAME__") (Name. (str v)) :else (AttributeBuilder/build ^String n (object-array [v])))))
        [op a b] expr]
    (case op
      :lit (when-not a (FilterBuilder/not (FilterBuilder/equalTo (Uid. "sling-nothing"))))
      :and (let [l (->filter c type a) r (->filter c type b)] (cond (nil? l) r (nil? r) l :else (FilterBuilder/and l r)))
      :or (let [l (->filter c type a) r (->filter c type b)] (when (and l r) (FilterBuilder/or l r)))
      :not (FilterBuilder/not (->filter c type a))
      :eq (FilterBuilder/equalTo (attr a b))
      :co (FilterBuilder/contains (attr a b))
      :sw (FilterBuilder/startsWith (attr a b))
      :gt (FilterBuilder/greaterThan (attr a b))
      :ge (FilterBuilder/greaterThanOrEqualTo (attr a b))
      :lt (FilterBuilder/lessThan (attr a b))
      :le (FilterBuilder/lessThanOrEqualTo (attr a b))
      :pr nil)))

(defn read-obj [{:keys [facade] :as c} type id]
  (some->> (.getObject facade (object-class c type) (Uid. (str id)) (.build (OperationOptionsBuilder.)))
           (->object c type)))

(defn search [{:keys [facade] :as c} type expr]
  (let [found (atom [])]
    (.search facade (object-class c type) (->filter c type expr)
             (reify ResultsHandler (handle [_ co] (swap! found conj (->object c type co)) true))
             (.build (OperationOptionsBuilder.)))
    ;; a script may ignore what it cannot express (pr, say): filter again, as IDM's view of it
    (filterv #(idm/matches? expr %) @found)))

(defn create! [{:keys [facade] :as c} type obj]
  (let [uid (.create facade (object-class c type) (->attributes c type obj) (.build (OperationOptionsBuilder.)))]
    (read-obj c type (.getUidValue uid))))

(defn update! [{:keys [facade] :as c} type id obj]
  (let [uid (.update facade (object-class c type) (Uid. (str id)) (->attributes c type obj) (.build (OperationOptionsBuilder.)))]
    (read-obj c type (.getUidValue uid))))

(defn delete! [{:keys [facade] :as c} type id]
  (.delete facade (object-class c type) (Uid. (str id)) (.build (OperationOptionsBuilder.))))
