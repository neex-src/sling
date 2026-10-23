(ns sling.idm
  "Managed objects the way /openidm answers for them: create, read, replace, patch, delete and
  query with _queryFilter, _fields, _sortKeys and paging. One store serves the REST endpoints,
  the openidm/idRepository bindings of journey scripts and the Data Store Decision node, so a user
  a service creates over REST can log in through a journey a second later.

  The store is an atom {\"alpha_user\" {id object}}. Objects carry :_id and :_rev; `password` is
  kept (it is a fake) but never read back, as on the platform.

  Query filters follow the documented grammar: `and`, `or`, `!`, parentheses, `true`/`false`,
  `pr`, and eq co sw lt le gt ge with quoted strings, numbers, booleans and null. String matches
  ignore case, as the directory's default matching rules do; a multi-valued field matches when
  any value does."
  (:require [clojure.string :as str]
            [sling.web :as web])
  (:import (java.util UUID)))

(def private-fields #{:password})

;; ---- _queryFilter --------------------------------------------------------------------------

(defn- tokens [s]
  (let [m (re-matcher #"\s*(\(|\)|!|\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'|[^\s()!]+)" s)]
    (loop [acc []]
      (if (.find m) (recur (conj acc (.group m 1))) acc))))

(defn- literal [t]
  (cond
    (nil? t) (throw (ex-info "query filter ends where a value should be" {}))
    (re-matches #"\".*\"|'.*'" t) (str/replace (subs t 1 (dec (count t))) #"\\(.)" "$1")
    (= t "true") true
    (= t "false") false
    (= t "null") nil
    (re-matches #"-?\d+" t) (parse-long t)
    (re-matches #"-?\d+\.\d+([eE][-+]?\d+)?" t) (parse-double t)
    :else (throw (ex-info (str "not a JSON value: " t) {:token t}))))

(defn- pointer [t] (mapv keyword (remove str/blank? (str/split t #"/"))))

(declare parse-or)

(defn- parse-primary [ts]
  (let [[t & more] ts]
    (cond
      (nil? t) (throw (ex-info "query filter ends too early" {}))
      (= t "(") (let [[e rest] (parse-or more)]
                  (if (= ")" (first rest)) [e (next rest)] (throw (ex-info "missing )" {}))))
      (= t "!") (let [[e rest] (parse-primary more)] [[:not e] rest])
      (#{"true" "false"} t) [[:lit (= t "true")] more]
      (= "pr" (first more)) [[:pr (pointer t)] (next more)]
      (#{"eq" "co" "sw" "lt" "le" "gt" "ge"} (first more))
      [[(keyword (first more)) (pointer t) (literal (second more))] (nnext more)]
      :else (throw (ex-info (str "cannot read the query filter at " (pr-str t)) {})))))

(defn- parse-and [ts]
  (loop [[e rest] (parse-primary ts)]
    (if (= "and" (first rest))
      (let [[e2 rest2] (parse-primary (next rest))] (recur [[:and e e2] rest2]))
      [e rest])))

(defn- parse-or [ts]
  (loop [[e rest] (parse-and ts)]
    (if (= "or" (first rest))
      (let [[e2 rest2] (parse-and (next rest))] (recur [[:or e e2] rest2]))
      [e rest])))

(defn parse-filter
  "The filter as a tree, e.g. [:and [:eq [:userName] \"bob\"] [:pr [:mail]]]. Throws ex-info on bad input."
  [s]
  (let [[e rest] (parse-or (tokens s))]
    (when (seq rest) (throw (ex-info (str "unexpected " (pr-str (first rest)) " in query filter") {})))
    e))

(defn- norm [v] (if (string? v) (str/lower-case v) v))

(defn- cmp [op a b]
  (let [a (norm a) b (norm b)]
    (case op
      :eq (= a b)
      :co (and (string? a) (string? b) (str/includes? a b))
      :sw (and (string? a) (string? b) (str/starts-with? a b))
      (and (some? a) (some? b) (= (type a) (type b))
           (let [c (compare a b)]
             (case op :lt (neg? c) :le (<= c 0) :gt (pos? c) :ge (>= c 0)))))))

(defn matches? [expr obj]
  (let [[op a b] expr]
    (case op
      :lit a
      :not (not (matches? a obj))
      :and (and (matches? a obj) (matches? b obj))
      :or (or (matches? a obj) (matches? b obj))
      :pr (let [v (get-in obj a)] (and (some? v) (not (and (coll? v) (empty? v))) (not= "" v)))
      (let [v (get-in obj a)]
        (if (sequential? v) (boolean (some #(cmp op % b) v)) (cmp op v b))))))

;; ---- the store -----------------------------------------------------------------------------

(defn public-view
  "What a read returns: no private fields, and only `fields` (nil or [\"*\"] = all) plus _id/_rev."
  [obj fields]
  (let [o (apply dissoc obj private-fields)
        fs (remove #(or (= % "*") (str/ends-with? % "_ref")) fields)]
    (if (seq fs)
      (reduce (fn [m f] (let [p (pointer f)] (if-some [v (get-in o p)] (assoc-in m p v) m)))
              (select-keys o [:_id :_rev]) fs)
      o)))

(defn- next-rev [obj] (str (inc (or (some-> (:_rev obj) parse-long) 0))))

(defn create! [store type obj]
  (let [id (or (:_id obj) (str (UUID/randomUUID)))
        o (assoc obj :_id id :_rev "1")]
    (swap! store assoc-in [type id] o)
    o))

(defn read-obj [store type id] (get-in @store [type id]))

(defn find-by
  "First object of `type` whose `field` equals `v` (ignoring case), or whose _id is `v`."
  [store type field v]
  (or (read-obj store type v)
      (first (filter #(= (norm (get % field)) (norm v)) (vals (get @store type))))))

(defn query
  "Run a CREST query over `type`. params are strings, as on the wire: _queryFilter, _fields,
  _sortKeys, _pageSize, _pagedResultsOffset, _pagedResultsCookie, _totalPagedResultsPolicy."
  [store type {:strs [_queryFilter _fields _sortKeys _pageSize _pagedResultsOffset _pagedResultsCookie
                      _totalPagedResultsPolicy]}]
  (let [expr (parse-filter (or _queryFilter "true"))
        found (filter #(matches? expr %) (vals (get @store type)))
        sorted (reduce (fn [xs k]
                         (let [desc (str/starts-with? k "-")
                               p (pointer (str/replace k #"^[-+]" ""))]
                           (cond-> (sort-by #(norm (get-in % p)) (fn [a b] (compare a b)) xs) desc reverse)))
                       (sort-by :_id found)
                       (reverse (remove str/blank? (str/split (or _sortKeys "") #","))))
        offset (or (some-> _pagedResultsCookie parse-long) (some-> _pagedResultsOffset parse-long) 0)
        size (some-> _pageSize parse-long)
        page (cond->> (drop offset sorted) size (take size))
        fields (some-> _fields (str/split #","))
        more? (and size (> (count sorted) (+ offset size)))]
    {:result (mapv #(public-view % fields) page)
     :resultCount (count page)
     :pagedResultsCookie (when more? (str (+ offset size)))
     :totalPagedResultsPolicy (if (= "EXACT" _totalPagedResultsPolicy) "EXACT" "NONE")
     :totalPagedResults (if (= "EXACT" _totalPagedResultsPolicy) (count sorted) -1)
     :remainingPagedResults -1}))

(defn- apply-op [obj {:keys [operation field value from]}]
  (let [p (pointer field)
        append? (= :- (peek p))
        p' (if append? (pop p) p)]
    (case operation
      "add" (if append? (update-in obj p' (fnil conj []) value)
                (let [cur (get-in obj p)]
                  (assoc-in obj p (if (sequential? cur) (into cur (if (sequential? value) value [value])) value))))
      "replace" (assoc-in obj p value)
      "remove" (if (= 1 (count p))
                 (if (some? value)
                   (update obj (first p) #(vec (remove #{value} %)))
                   (dissoc obj (first p)))
                 (update-in obj (pop p) dissoc (peek p)))
      "increment" (update-in obj p (fnil + 0) value)
      "copy" (assoc-in obj p (get-in obj (pointer from)))
      "move" (let [v (get-in obj (pointer from))] (-> obj (dissoc (first (pointer from))) (assoc-in p v)))
      (throw (ex-info (str "patch operation " (pr-str operation) " is not supported") {})))))

(defn patch! [store type id ops]
  (when (read-obj store type id)
    (let [o (-> (reduce apply-op (read-obj store type id) ops) (assoc :_id id))
          o (assoc o :_rev (next-rev (read-obj store type id)))]
      (swap! store assoc-in [type id] o)
      o)))

(defn replace! [store type id obj]
  (let [old (read-obj store type id)
        o (assoc obj :_id id :_rev (if old (next-rev old) "1"))]
    (swap! store assoc-in [type id] (cond-> o (and old (nil? (:password obj)) (:password old)) (assoc :password (:password old))))
    o))

(defn delete! [store type id]
  (when-let [o (read-obj store type id)]
    (swap! store update type dissoc id)
    o))

;; ---- REST ----------------------------------------------------------------------------------

(defn handle
  "/openidm/managed/<type>[/<id>]. `allowed?` is the caller's check of the bearer token."
  [store req type id]
  (let [m (:method req)
        action (web/param req "_action")
        fields (some-> (web/param req "_fields") (str/split #","))
        rev-ok? (fn [o] (let [want (web/header req "if-match")]
                          (or (nil? want) (= want "*") (= want (:_rev o)))))
        body (delay (web/json-body req))
        out (fn [status o] (web/json status (public-view o fields)))]
    (try
      (cond
        (and (nil? id) (= m "GET"))
        (if (web/param req "_queryFilter")
          (web/json 200 (query store type (update-vals (:query req) first)))
          (web/error 400 "query requests need _queryFilter (use _queryFilter=true for all)"))

        (and (nil? id) (= m "POST") (contains? #{nil "create"} action))
        (if (and (:_id @body) (read-obj store type (:_id @body)))
          (web/error 412 "object already exists")
          (out 201 (create! store type @body)))

        (nil? id) (web/error 405 (str m " on a collection"))

        (= m "GET") (if-let [o (read-obj store type id)] (out 200 o) (web/error 404 (str "managed/" type "/" id " not found")))

        (= m "PUT") (let [old (read-obj store type id)]
                      (cond
                        (and old (= "*" (web/header req "if-none-match"))) (web/error 412 "object already exists")
                        (and old (not (rev-ok? old))) (web/error 412 "revision does not match")
                        old (out 200 (replace! store type id @body))
                        :else (out 201 (create! store type (assoc @body :_id id)))))

        (or (= m "PATCH") (and (= m "POST") (= action "patch")))
        (if-let [old (read-obj store type id)]
          (if (rev-ok? old) (out 200 (patch! store type id @body)) (web/error 412 "revision does not match"))
          (web/error 404 (str "managed/" type "/" id " not found")))

        (= m "DELETE") (if-let [o (delete! store type id)] (out 200 o) (web/error 404 (str "managed/" type "/" id " not found")))

        :else (web/error 405 (str m " " (or action ""))))
      (catch clojure.lang.ExceptionInfo e
        (web/error 400 (ex-message e))))))
