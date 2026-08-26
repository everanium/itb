(ns dev.everanium.itb.clojure.bench-util
  "Shared timing + reporting helpers for the Clojure binding
  micro-benchmarks. Wall-clock via System/nanoTime; output is a
  fixed-width table:

    bench             size     mb_per_sec
    message           1 MiB    <n>
    ...

  Bench configuration is driven by environment variables so a
  side-by-side comparison with the root Go bench harness is
  straightforward:

    ITB_NONCE_BITS     nonce width (default 512)
    ITB_KEY_BITS       key bits (default 1024)
    ITB_WITH_PARALLAX  parallax layer on/off (default false)
    ITB_WITH_WRAPPER   wrapper layer on/off (default false)
    ITB_INNER_HASH     opaque hash name (default: profile's)
    ITB_PROFILE        profile name override
    ITB_BENCH_MIN_SEC  per-case wall-clock budget (default 5.0)"
  (:require [dev.everanium.itb.clojure.runtime :as runtime])
  (:import [java.security SecureRandom]))

(def sizes
  "Payload sizes exercised by both shapes."
  [(bit-shift-left 1 20) (bit-shift-left 16 20) (bit-shift-left 64 20)])

(def ^:private min-iters
  "Iteration floor per case."
  3)

(def ^:private ^SecureRandom csprng (SecureRandom.))

(defn- env ^String [name]
  (let [v (System/getenv ^String name)]
    (when (seq v) v)))

(defn- env-long ^long [name fallback]
  (if-let [v (env name)] (Long/parseLong v) (long fallback)))

(defn- env-bool [name]
  (contains? #{"true" "1"} (System/getenv ^String name)))

(defn min-seconds ^double []
  (let [v (some-> (env "ITB_BENCH_MIN_SEC") Double/parseDouble)]
    (if (and v (pos? (double v))) (double v) 5.0)))

(defn build-opts
  "Reads the bench-shape env vars and builds an opts map. Defaults
  match root Go BENCH3.md so numbers are directly comparable."
  []
  (cond-> {:nonce-bits (env-long "ITB_NONCE_BITS" 512)
           :key-bits (env-long "ITB_KEY_BITS" 1024)
           :parallax? (env-bool "ITB_WITH_PARALLAX")
           :wrapper? (env-bool "ITB_WITH_WRAPPER")}
    (env "ITB_INNER_HASH") (assoc :inner-hash (env "ITB_INNER_HASH"))
    (env "ITB_MAC_NAME") (assoc :mac-name (env "ITB_MAC_NAME"))))

(defn profile-name [fallback]
  (or (env "ITB_PROFILE") fallback))

(defn apply-runtime-caps!
  "Go-runtime pacing caps for bench-scale allocation churn;
  run_bench.sh exports the same defaults via ITB_GOMEMLIMIT /
  ITB_GOGC as a fallback."
  []
  (runtime/set-memory-limit! (bit-shift-left 512 20))
  (runtime/set-gc-percent! 20))

(defn header []
  (println (format "%-17s %-8s %s" "bench" "size" "mb_per_sec")))

(defn csprng-fill
  "CSPRNG-fill so plaintext content matches the root Go bench
  (crypto/rand). Not called inside timing loops."
  [^bytes buf]
  (.nextBytes csprng buf))

(defn- size-label [size]
  (if (>= (long size) (bit-shift-left 1 20))
    (str (bit-shift-right (long size) 20) " MiB")
    (str (bit-shift-right (long size) 10) " KiB")))

(defn bench-case
  "Runs `run` until the wall-clock budget is spent (with an
  iteration floor + one untimed warm-up), then prints one table
  row."
  [case-name size run]
  (run) ; warm-up
  (let [budget-nanos (long (* (min-seconds) 1e9))
        start (System/nanoTime)
        iters (loop [iters 0]
                (if (or (< (- (System/nanoTime) start) budget-nanos)
                        (< iters min-iters))
                  (do (run) (recur (inc iters)))
                  iters))
        elapsed (/ (- (System/nanoTime) start) 1e9)
        mb (/ (* (double size) iters) (* 1024.0 1024.0))]
    (println (format "%-17s %-8s %.1f" case-name (size-label size) (/ mb elapsed)))))
