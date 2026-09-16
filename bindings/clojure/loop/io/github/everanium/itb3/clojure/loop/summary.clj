(ns io.github.everanium.itb3.clojure.loop.summary
  "The final summary in both renderings, and the two measurements it
  folds in that are not per-worker counters: the process resident set
  and the shared library's pool counters."
  (:require [clojure.string :as str]
            [io.github.everanium.itb3.clojure.loop.payload :as payload]
            [io.github.everanium.itb3.clojure.loop.size :as size]
            [io.github.everanium.itb3.clojure.loop.state :as state]
            [io.github.everanium.itb3.clojure.loop.worker :as worker]
            [io.github.everanium.itb3.clojure.runtime :as runtime])
  (:import [java.nio.file Files Path]
           [java.util Locale]))

(defn- status-kb
  "Parses one \"Vm...:   1234 kB\" line of /proc/self/status into
  bytes; zero on any parse failure."
  ^long [^String line]
  (let [colon (.indexOf line (int \:))]
    (if (neg? colon)
      0
      (let [first-field (first (str/split (str/trim (subs line (inc colon))) #"\s+"))]
        (try
          (* 1024 (Long/parseLong first-field))
          (catch Exception _ 0))))))

(defn read-rss
  "The process's current resident set and its high-water mark in
  bytes, from /proc/self/status (VmRSS and VmHWM, reported in kB).
  Both are zero on a platform without that file; the figures are
  informational and never enter the verdict."
  []
  (try
    ;; Clojure-specific. The file is read through the NIO line reader
    ;; rather than slurped: a procfs entry reports no length, and the
    ;; stream decoder behind the whole-file reader asks the descriptor
    ;; how many bytes are available before it decodes any.
    (reduce (fn [[current peak] ^String line]
              (cond
                (.startsWith line "VmRSS:") [(status-kb line) peak]
                (.startsWith line "VmHWM:") [current (status-kb line)]
                :else [current peak]))
            [0 0]
            (Files/readAllLines (Path/of "/proc/self/status" (into-array String []))))
    (catch Exception _ [0 0])))

(defn pool-snapshot
  "Pool counters. The shared library keeps process-wide monotonic
  totals at every pool checkout of its cipher core: per hash-array
  tier the starter width, checkouts, constructor misses, regrow
  replacements and bytes allocated; for the scratch byte pool and the
  parallax chunk pool the checkouts, constructor misses, regrows and
  regrow bytes. Two snapshots bracketing the main loop are differenced
  into per-run hit / miss figures that tell whether a pool keeps its
  items warm between calls or evicts them across GC cycles. The slot
  layout is read from the library: slot 0 carries the tier count T,
  tier i occupies the five slots at 1 + 5*i, and the two byte pools
  occupy the eight slots at 1 + 5*T; the vector is sized by the
  binding from the library's own length query, never from a constant.
  Empty when the library is unavailable."
  ^longs []
  (try
    (runtime/pool-stats)
    (catch Exception _ (long-array 0))))

(defn- pool-diff
  "Differences the shutdown snapshot against the warmup baseline into
  the per-tier and per-byte-pool figures the summary reports."
  [^longs steady ^longs warmup]
  (let [empty-delta {:tiers [] :buf {:get 0 :fresh 0 :regrow 0 :regrow-bytes 0}
                     :chunk {:get 0 :fresh 0 :regrow 0 :regrow-bytes 0}}]
    (if (or (< (alength steady) 9) (not= (alength warmup) (alength steady)))
      empty-delta
      (let [tiers (aget steady 0)]
        (if (or (neg? tiers) (> (+ 1 (* 5 tiers) 8) (alength steady)))
          empty-delta
          (let [t (int (+ 1 (* 5 tiers)))]
            {:tiers (into []
                          (comp (map (fn [^long i]
                                       (let [b (int (+ 1 (* 5 i)))]
                                         (when-not (zero? (aget steady b))
                                           {:index i
                                            :starter (aget steady b)
                                            :get (- (aget steady (+ b 1)) (aget warmup (+ b 1)))
                                            :fresh (- (aget steady (+ b 2)) (aget warmup (+ b 2)))
                                            :regrow (- (aget steady (+ b 3)) (aget warmup (+ b 3)))
                                            :new-bytes (- (aget steady (+ b 4))
                                                          (aget warmup (+ b 4)))}))))
                                (remove nil?))
                          (range tiers))
             :buf {:get (- (aget steady t) (aget warmup t))
                   :fresh (- (aget steady (+ t 1)) (aget warmup (+ t 1)))
                   :regrow (- (aget steady (+ t 2)) (aget warmup (+ t 2)))
                   :regrow-bytes (- (aget steady (+ t 3)) (aget warmup (+ t 3)))}
             :chunk {:get (- (aget steady (+ t 4)) (aget warmup (+ t 4)))
                     :fresh (- (aget steady (+ t 5)) (aget warmup (+ t 5)))
                     :regrow (- (aget steady (+ t 6)) (aget warmup (+ t 6)))
                     :regrow-bytes (- (aget steady (+ t 7)) (aget warmup (+ t 7)))}}))))))

(defn- miss-percent
  "Misses over checkouts as a percentage; zero when nothing was
  checked out."
  ^double [^long miss ^long get-count]
  (if (<= get-count 0)
    0.0
    (/ (* 100.0 miss) get-count)))

(defn- json-string
  "Renders s as a JSON string literal with the escapes JSON requires."
  ^String [^String s]
  (let [sb (StringBuilder. (+ 2 (.length s)))]
    (.append sb \")
    (dotimes [i (.length s)]
      (let [ch (.charAt s i)]
        (cond
          (= ch \") (.append sb "\\\"")
          (= ch \\) (.append sb "\\\\")
          (= ch \newline) (.append sb "\\n")
          (= ch \return) (.append sb "\\r")
          (= ch \tab) (.append sb "\\t")
          (< (int ch) 32) (.append sb (String/format Locale/ROOT "\\u%04x"
                                                     (object-array [(int ch)])))
          :else (.append sb ch))))
    (.append sb \")
    (.toString sb)))

(defn- effective-gogc
  "The effective GC percentage as the runtime reports it: the query
  form of the setter (a set-and-restore round trip inside the library)
  so the field is the same whether the value came from the flag, the
  environment, or the runtime default."
  ^long [^long flag]
  (if (pos? flag)
    flag
    (try
      (runtime/set-gc-percent! -1)
      (catch Exception _ 0))))

(defn emit-summary
  "Output contract. Both renderings are shared with the Go harness and
  every other binding's loop utility field for field: the same lines
  in the same order, the same keys in the same order, floats with a
  fixed number of decimals so the JSON is byte-identical across
  implementations. The Go harness alone adds its runtime-internal
  lines after rss: and its runtime-internal keys after
  parallax_chunk_pool; nothing here reproduces them because nothing
  they read is reachable through the C ABI. Returns the exit code."
  ^long [r ^long elapsed-ns m]
  (let [cfg (:cfg r)
        workers (long (:workers cfg))
        per-worker (mapv #(state/counter-value % :iters) (:counters r))
        total-iters (reduce + 0 per-worker)
        total-enc (reduce + 0 (map #(state/counter-value % :bytes-enc) (:counters r)))
        total-dec (reduce + 0 (map #(state/counter-value % :bytes-dec) (:counters r)))
        nanos-enc (reduce + 0 (map #(state/counter-value % :nanos-enc) (:counters r)))
        nanos-dec (reduce + 0 (map #(state/counter-value % :nanos-dec) (:counters r)))
        errors (into [] (keep #(deref (:error %))) (:counters r))
        ;; Throughput. Per-direction throughput divides the sum of
        ;; every worker's wall time in that direction by the worker
        ;; count — the equivalent single-stream wall time under N-way
        ;; concurrency — so each direction reports the aggregate rate
        ;; it sustained rather than collapsing to combined/2 (every
        ;; iteration moves equal encrypt and decrypt bytes, so a
        ;; total-elapsed denominator would give both directions the
        ;; same figure). The combined rate keeps total elapsed as the
        ;; one-glance overall figure.
        avg-enc (if (pos? (long nanos-enc)) (quot (long nanos-enc) workers) 0)
        avg-dec (if (pos? (long nanos-dec)) (quot (long nanos-dec) workers) 0)
        rss-warmup (long (:rss-warmup m))
        rss-final (long (:rss-final m))
        rss-peak (long (:rss-peak m))
        rss-delta (- rss-final rss-warmup)
        rss-growth (if (pos? rss-warmup) (/ (* 100.0 rss-delta) rss-warmup) 0.0)
        pd (pool-diff (:pool-steady m) (:pool-warmup m))
        pass? (empty? errors)
        rekeys (state/counter-value r :rekeys)
        cycles (state/counter-value r :blob-cycles)
        gomaxprocs (try (runtime/set-gomaxprocs! 0) (catch Exception _ 0))
        pipes @(:pipes r)
        stream-profile (if (:stream pipes) (:stream-profile r) "")
        msg-profile (if (:msg pipes) (:msg-profile r) "")]
    (if (:json-output cfg)
      (let [j (StringBuilder.)]
        (doto j
          (.append "{\"duration_seconds\":") (.append (size/f (/ elapsed-ns 1e9) 3))
          (.append ",\"iterations\":") (.append (long total-iters))
          (.append ",\"per_worker_iterations\":[")
          (.append (str/join "," per-worker)) (.append \])
          (.append ",\"bytes_encrypted\":") (.append (long total-enc))
          (.append ",\"bytes_decrypted\":") (.append (long total-dec))
          (.append ",\"encrypt_mb_per_sec\":")
          (.append (size/f (size/mb-per-sec total-enc avg-enc) 1))
          (.append ",\"decrypt_mb_per_sec\":")
          (.append (size/f (size/mb-per-sec total-dec avg-dec) 1))
          (.append ",\"combined_mb_per_sec\":")
          (.append (size/f (size/mb-per-sec (+ (long total-enc) (long total-dec)) elapsed-ns) 1))
          (.append ",\"rekeys\":") (.append rekeys)
          (.append ",\"blob_cycles\":") (.append cycles)
          (.append ",\"worker_errors\":[")
          (.append (str/join "," (map json-string errors))) (.append \])
          (.append ",\"verdict\":\"") (.append (if pass? "PASS" "FAIL")) (.append \")
          (.append ",\"shape\":\"") (.append ^String (worker/shape-label (:shape cfg)))
          (.append \")
          (.append ",\"stream_profile\":") (.append (json-string stream-profile))
          (.append ",\"message_profile\":") (.append (json-string msg-profile))
          (.append ",\"hash\":") (.append (json-string (:hash cfg)))
          (.append ",\"mac\":") (.append (json-string (:mac cfg)))
          (.append ",\"payload_bytes\":") (.append (long (:payload cfg)))
          (.append ",\"payload_mode\":\"")
          (.append ^String (payload/mode-label (:payload-mode cfg))) (.append \")
          (.append ",\"seed\":") (.append (Long/toUnsignedString (long (:seed cfg))))
          (.append ",\"key_bits\":") (.append (long (:key-bits cfg)))
          (.append ",\"nonce_bits\":") (.append (long (:nonce-bits cfg)))
          (.append ",\"chunk_size_bytes\":") (.append (long (:chunk-size cfg)))
          (.append ",\"barrier_fill\":") (.append (long (:barrier-fill cfg)))
          (.append ",\"parallax\":\"") (.append (state/on-off (:parallax cfg))) (.append \")
          (.append ",\"wrapper\":\"") (.append (state/on-off (:wrapper cfg))) (.append \")
          (.append ",\"goroutines_requested\":") (.append (long (:workers-requested cfg)))
          (.append ",\"goroutines\":") (.append workers)
          (.append ",\"concurrency\":\"") (.append ^String state/concurrency) (.append \")
          (.append ",\"gogc\":\"") (.append (effective-gogc (long (:gogc cfg)))) (.append \")
          (.append ",\"memlimit_bytes\":") (.append (long (:memlimit cfg)))
          (.append ",\"gomaxprocs\":") (.append (long gomaxprocs))
          (.append ",\"microbatch_tiers\":")
          (.append (json-string (state/policy-label "ITB_MICROBATCH_TIERS")))
          (.append ",\"hashpool_starters\":")
          (.append (json-string (state/policy-label "ITB_HASHPOOL_STARTERS")))
          (.append ",\"rss_warmup_bytes\":") (.append rss-warmup)
          (.append ",\"rss_peak_bytes\":") (.append rss-peak)
          (.append ",\"rss_final_bytes\":") (.append rss-final)
          (.append ",\"rss_growth_percent\":") (.append (size/f rss-growth 2))
          (.append ",\"hash_pool_tiers\":[")
          (.append (str/join ","
                             (map (fn [t]
                                    (str "{\"tier\":" (:index t)
                                         ",\"starter\":" (:starter t)
                                         ",\"get\":" (:get t)
                                         ",\"new\":" (:fresh t)
                                         ",\"regrow\":" (:regrow t)
                                         ",\"new_bytes\":" (:new-bytes t)
                                         ",\"miss_percent\":"
                                         (size/f (miss-percent (+ (long (:fresh t))
                                                                  (long (:regrow t)))
                                                               (:get t))
                                                 2)
                                         "}"))
                                  (:tiers pd))))
          (.append \])
          (.append ",\"buf_pool\":{\"get\":") (.append (long (:get (:buf pd))))
          (.append ",\"new\":") (.append (long (:fresh (:buf pd))))
          (.append ",\"regrow\":") (.append (long (:regrow (:buf pd))))
          (.append ",\"regrow_bytes\":") (.append (long (:regrow-bytes (:buf pd))))
          (.append ",\"miss_percent\":")
          (.append (size/f (miss-percent (:regrow (:buf pd)) (:get (:buf pd))) 2))
          (.append \})
          (.append ",\"parallax_chunk_pool\":{\"get\":") (.append (long (:get (:chunk pd))))
          (.append ",\"new\":") (.append (long (:fresh (:chunk pd))))
          (.append ",\"regrow\":") (.append (long (:regrow (:chunk pd))))
          (.append ",\"regrow_bytes\":") (.append (long (:regrow-bytes (:chunk pd))))
          (.append ",\"miss_percent\":")
          (.append (size/f (miss-percent (:regrow (:chunk pd)) (:get (:chunk pd))) 2))
          (.append \})
          (.append \}))
        (println (.toString j))
        (if pass? 0 1))
      (do
        (state/log-line "=== FINAL ===")
        (state/log-line (str "  duration: " (size/human-duration (size/round-to elapsed-ns 1000000))))
        (state/log-line (str "  iterations: " (str/join " + " per-worker)
                             " = " total-iters " total"))
        (state/log-line (str "  throughput: encrypt " (size/human-rate total-enc avg-enc)
                             ", decrypt " (size/human-rate total-dec avg-dec)
                             ", combined " (size/human-rate (+ (long total-enc) (long total-dec))
                                                            elapsed-ns)))
        (state/log-line (str "  bytes: " (size/human-bytes total-enc) " encrypted, "
                             (size/human-bytes total-dec) " decrypted"))
        (state/log-line (str "  data integrity: " total-iters "/" total-iters " PASS"))
        (state/log-line (str "  concurrency: " state/concurrency
                             ", workers " workers
                             " (requested " (:workers-requested cfg) ")"))
        (state/log-line (str "  rss: warmup " (size/human-bytes rss-warmup)
                             ", peak " (size/human-bytes rss-peak)
                             ", final " (size/human-bytes rss-final)
                             " (delta " (size/human-bytes-signed rss-delta)
                             ", " (size/f rss-growth 1) "% growth)"))
        (doseq [t (:tiers pd)]
          (state/log-line (str "  hash pool tier " (:index t)
                               " (starter " (:starter t) "): get " (:get t)
                               ", miss " (+ (long (:fresh t)) (long (:regrow t)))
                               " (new " (:fresh t) " + regrow " (:regrow t) ")"
                               ", miss " (size/f (miss-percent (+ (long (:fresh t))
                                                                  (long (:regrow t)))
                                                               (:get t))
                                                 2)
                               "%, " (size/human-bytes (:new-bytes t)) " allocated")))
        (state/log-line (str "  buf pool: get " (:get (:buf pd))
                             ", regrow " (:regrow (:buf pd))
                             " (of which fresh " (:fresh (:buf pd)) ")"
                             ", miss " (size/f (miss-percent (:regrow (:buf pd))
                                                             (:get (:buf pd)))
                                               2)
                             "%, " (size/human-bytes (:regrow-bytes (:buf pd))) " regrown"))
        (state/log-line (str "  parallax chunk pool: get " (:get (:chunk pd))
                             ", regrow " (:regrow (:chunk pd))
                             " (of which fresh " (:fresh (:chunk pd)) ")"
                             ", miss " (size/f (miss-percent (:regrow (:chunk pd))
                                                             (:get (:chunk pd)))
                                               2)
                             "%, " (size/human-bytes (:regrow-bytes (:chunk pd))) " regrown"))
        (when (pos? rekeys)
          (state/log-line (str "  rekeys: " rekeys)))
        (when (pos? cycles)
          (state/log-line (str "  blob cycles: " cycles)))
        (doseq [e errors]
          (state/log-line (str "  ERROR: " e)))
        (if pass?
          (do (state/log-line "  verdict: PASS") 0)
          (do (state/log-line (str "  verdict: FAIL (errors=" (count errors) ")")) 1))))))
