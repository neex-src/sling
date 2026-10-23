(ns sling.frodojson
  "JSON exactly as Frodo writes its export files, so a file the fake writes back diffs only where
  the content changed: JSON.stringify(x, replacer, 2) with Frodo's key-sorting replacer, plus a
  trailing newline.

  What that means in detail: object keys sorted by UTF-16 code units, except that keys which are
  array indices (\"0\", \"17\") come first in numeric order, as JavaScript objects keep them; two
  spaces per level, \"key\": value, one array element per line, {} and [] when empty; strings
  escaped as JSON.stringify does (only \\\" \\\\ and control characters, lower-case \\u00xx);
  integral numbers without a fraction.

  Keys may be keywords (cheshire's :key-fn true); a namespaced one such as :endpoint/x is written
  as \"endpoint/x\"."
  (:require [clojure.string :as str]))

(defn key-str [k] (if (keyword? k) (subs (str k) 1) (str k)))

(defn- index-key? [^String s]
  (boolean (and (re-matches #"0|[1-9]\d*" s) (< (parse-long s) 4294967295))))

(defn- ordered-keys [m]
  (let [ks (map key-str (keys m))
        {idx true other false} (group-by index-key? ks)]
    (concat (sort-by parse-long idx) (sort other))))

(defn- escape [^String s]
  (let [sb (StringBuilder. "\"")]
    (doseq [c s]
      (case c
        \" (.append sb "\\\"")
        \\ (.append sb "\\\\")
        \newline (.append sb "\\n")
        \return (.append sb "\\r")
        \tab (.append sb "\\t")
        \backspace (.append sb "\\b")
        \formfeed (.append sb "\\f")
        (if (< (int c) 0x20)
          (.append sb (format "\\u%04x" (int c)))
          (.append sb c))))
    (str (.append sb "\""))))

(defn- number-str [n]
  (cond
    (integer? n) (str n)
    (and (float? n) (== n (Math/rint n)) (< (Math/abs (double n)) 1e21)) (str (long n))
    :else (str n)))

(defn- write [^StringBuilder sb x indent]
  (let [pad (fn [n] (.append sb "\n") (dotimes [_ n] (.append sb "  ")))]
    (cond
      (nil? x) (.append sb "null")
      (boolean? x) (.append sb (str x))
      (number? x) (.append sb (number-str x))
      (string? x) (.append sb (escape x))
      (keyword? x) (.append sb (escape (key-str x)))
      (map? x) (let [by-str (into {} (map (fn [[k v]] [(key-str k) v]) x))
                     ks (ordered-keys x)]
                 (if (empty? ks)
                   (.append sb "{}")
                   (do (.append sb "{")
                       (doseq [[i k] (map-indexed vector ks)]
                         (when (pos? i) (.append sb ","))
                         (pad (inc indent))
                         (.append sb (escape k)) (.append sb ": ")
                         (write sb (by-str k) (inc indent)))
                       (pad indent)
                       (.append sb "}"))))
      (sequential? x) (if (empty? x)
                        (.append sb "[]")
                        (do (.append sb "[")
                            (doseq [[i v] (map-indexed vector x)]
                              (when (pos? i) (.append sb ","))
                              (pad (inc indent))
                              (write sb v (inc indent)))
                            (pad indent)
                            (.append sb "]")))
      :else (.append sb (escape (str x))))
    sb))

(defn stringify
  "The text Frodo would write for `x`, without the trailing newline."
  [x]
  (str (write (StringBuilder.) x 0)))

(defn file-text [x] (str (stringify x) "\n"))
