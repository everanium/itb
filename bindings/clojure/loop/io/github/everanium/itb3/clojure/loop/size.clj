(ns io.github.everanium.itb3.clojure.loop.size
  "Size and duration parsing and the human renderings of sizes, rates
  and durations. Every rendering here is part of the output contract
  shared with the Go harness and the other bindings' loop utilities,
  so the formats are fixed to the character, not to taste.

  Clojure-specific. Every formatter names Locale/ROOT explicitly:
  clojure.core/format renders through the ambient default locale,
  which turns \"1.5MB/s\" into \"1,5MB/s\" the day the harness runs
  under a comma-decimal locale, and the output contract is
  byte-for-byte."
  (:require [clojure.string :as str])
  (:import [java.util Locale]))

(def ^:private size-suffixes
  "Suffix table for `parse-size`, matched in order so the longer
  spellings win over their prefixes."
  [["KIB" 1024] ["KB" 1024] ["K" 1024]
   ["MIB" 1048576] ["MB" 1048576] ["M" 1048576]
   ["GIB" 1073741824] ["GB" 1073741824] ["G" 1073741824]
   ["B" 1]])

(defn- digits? [^String s]
  (and (pos? (.length s))
       (loop [i 0]
         (if (= i (.length s))
           true
           (let [c (.charAt s i)]
             (if (or (< (int c) 48) (> (int c) 57))
               false
               (recur (inc i))))))))

(defn parse-size
  "Parses a human byte-size string (\"16MB\", \"1MiB\", \"512K\",
  \"1073741824\") into a byte count. Every suffix is a binary
  multiple: K/KB/KiB = 1024, M/MB/MiB = 1024^2, G/GB/GiB = 1024^3, B
  or none = bytes; matching is case-insensitive and surrounding
  whitespace is trimmed. Nil on a malformed or negative value."
  [s]
  (let [upper (.toUpperCase (.trim ^String s) Locale/ROOT)]
    (when (pos? (.length upper))
      (let [hit (some (fn [[^String suffix mult]]
                        (when (.endsWith upper suffix)
                          [mult (subs upper 0 (- (.length upper) (.length suffix)))]))
                      size-suffixes)
            [mult body] (or hit [1 upper])
            body (str/trimr body)]
        (when (digits? body)
          (try
            (Math/multiplyExact (Long/parseLong body) (long mult))
            (catch NumberFormatException _ nil)
            (catch ArithmeticException _ nil)))))))

(def ^:private duration-units
  "Unit table for `parse-duration`, matched in order so \"ms\" wins
  over \"m\" followed by a stray \"s\"."
  [["ns" 1.0] ["us" 1e3] ["ms" 1e6] ["s" 1e9] ["m" 60e9] ["h" 3600e9]])

(defn parse-duration
  "Parses the Go duration grammar — a sequence of decimal numbers each
  followed by a unit (h, m, s, ms, us, ns), such as \"30s\", \"5m\",
  \"1h30m\", \"1.5s\" — into nanoseconds. Nil on a malformed string."
  [^String s]
  (when (pos? (.length s))
    (loop [rest s
           total 0.0]
      (if (zero? (.length ^String rest))
        (when (<= total 9.2e18)
          (long total))
        (let [^String rest rest
              num-len (loop [i 0]
                        (if (and (< i (.length rest))
                                 (let [c (.charAt rest i)]
                                   (or (and (>= (int c) 48) (<= (int c) 57)) (= c \.))))
                          (recur (inc i))
                          i))]
          (when (pos? num-len)
            (let [v (try
                      (Double/parseDouble (subs rest 0 num-len))
                      (catch NumberFormatException _ nil))
                  tail (subs rest num-len)
                  hit (some (fn [[^String unit ^double nanos]]
                              (when (.startsWith ^String tail unit)
                                (let [after (subs tail (.length unit))]
                                  ;; A unit whose next character is a
                                  ;; letter is the prefix of a longer
                                  ;; token that is not a unit at all.
                                  (when-not (and (pos? (.length ^String after))
                                                 (Character/isLetter (.charAt ^String after 0)))
                                    [after nanos]))))
                            duration-units)]
              (when (and v hit)
                (recur (first hit) (+ total (* (double v) (double (second hit)))))))))))))

(defn f
  "Fixed-decimal float rendering, locale-independent."
  ^String [^double v ^long decimals]
  (String/format Locale/ROOT (str "%." decimals "f") (object-array [v])))

(defn human-bytes
  "Renders a byte count with a binary-unit suffix: \"1.0GiB\",
  \"16.0MiB\", \"4.0KiB\", \"512B\"."
  ^String [^long n]
  (cond
    (>= n 1073741824) (str (f (/ (double n) 1073741824.0) 1) "GiB")
    (>= n 1048576) (str (f (/ (double n) 1048576.0) 1) "MiB")
    (>= n 1024) (str (f (/ (double n) 1024.0) 1) "KiB")
    :else (str n "B")))

(defn human-bytes-signed
  "Renders a possibly-negative byte delta with an explicit sign."
  ^String [^long n]
  (if (neg? n)
    (str "-" (human-bytes (- n)))
    (str "+" (human-bytes n))))

(defn mb-per-sec
  "Binary MiB per second over a nanosecond window; zero when the
  window is unmeasured."
  ^double [^long bytes ^long nanos]
  (if (<= nanos 0)
    0.0
    (/ (/ (double bytes) 1048576.0) (/ (double nanos) 1e9))))

(defn human-rate
  "Renders a throughput as \"123.4MB/s\" (binary MiB per second) or
  \"n/a\" for an unmeasured window."
  ^String [^long bytes ^long nanos]
  (if (<= nanos 0)
    "n/a"
    (str (f (mb-per-sec bytes nanos) 1) "MB/s")))

(defn- fraction
  "The fractional part of a nanosecond remainder (0 .. 1e9) as
  \".ddd\" with trailing zeros removed; empty for zero."
  ^String [^long frac-ns]
  (if (zero? frac-ns)
    ""
    (str "." (str/replace (String/format Locale/ROOT "%09d" (object-array [frac-ns]))
                          #"0+$" ""))))

(defn human-duration
  "Renders a duration the way Go's time.Duration prints: zero as
  \"0s\"; below one second as milliseconds (\"900ms\", \"1.5ms\");
  otherwise \"[Hh][Mm]Ss\" where the hour part appears when non-zero,
  the minute part when the hour part appears or the minutes are
  non-zero, and the seconds carry their fraction with trailing zeros
  removed (\"5s\", \"5.003s\", \"1m0s\", \"1m5.25s\", \"1h0m0s\"). The
  caller rounds first."
  ^String [^long nanos]
  (let [ns (Math/abs nanos)]
    (cond
      (zero? ns) "0s"
      (< ns 1000000000)
      (str (quot ns 1000000) (fraction (* (rem ns 1000000) 1000)) "ms")
      :else
      (let [hours (quot ns 3600000000000)
            rem1 (rem ns 3600000000000)
            minutes (quot rem1 60000000000)
            rem2 (rem rem1 60000000000)
            seconds (quot rem2 1000000000)
            frac (rem rem2 1000000000)
            sb (StringBuilder.)]
        (when (pos? hours)
          (.append sb hours)
          (.append sb "h"))
        (when (or (pos? hours) (pos? minutes))
          (.append sb minutes)
          (.append sb "m"))
        (.append sb seconds)
        (.append sb (fraction frac))
        (.append sb "s")
        (.toString sb)))))

(defn round-to
  "Rounds a nanosecond count to the nearest multiple of `unit-ns`."
  ^long [^long nanos ^long unit-ns]
  (* (quot (+ nanos (quot unit-ns 2)) unit-ns) unit-ns))
