(ns io.github.everanium.itb3.clojure.loop.main
  "Long-run stress harness. The loop utility holds one Pipeline handle
  per exercised cipher surface for minutes, hammers it with concurrent
  encrypt → decrypt → compare round-trips from N worker threads,
  rotates the outer masters and reopens the handle from its session
  blob on a schedule, and reports whether the process survived with
  every byte intact. It is the Clojure binding's counterpart of the Go
  harness under tools/loop: the same flags, the same round structure,
  the same summary in both renderings.

  The default shape is full production: the Streaming AEAD profile
  with parallax on, wrapper on, hmac-blake3 MAC, Areion-SoEM-512 inner
  hash, 1024-bit keys, and the profile's 512-bit nonce width, driven
  through a stream session by three workers for five minutes on 16 MiB
  plaintexts. Every worker owns a distinct CSPRNG-generated plaintext
  held for the whole run, so any cross-call state leakage inside the
  Pipeline surfaces as a data mismatch between workers rather than
  cancelling out.

  A failure is one of two things. A cipher, rekey or load call that
  returns a non-OK status is a worker error: the run stops, the
  summary lists it, the verdict is FAIL and the exit code 1. A
  round-trip that returns without error but with different bytes is a
  data mismatch: the process terminates on the spot with exit code 3,
  printing the worker, the iteration and the first differing offset,
  and no summary — the state that produced the wrong bytes is the
  evidence. A crash inside the shared library or the host runtime has
  no exit code of its own here; surfacing it is what the utility is
  for. Every call goes through the Clojure binding's own namespaces,
  which sit on the Java binding's JNI proxy, so a Go c-shared runtime
  and a HotSpot JVM share one process — the interaction the long run
  is meant to expose.

  Usage:

    ./run_loop.sh --duration 5m --goroutines 3 --shape stream \\
        --hash areion512 --mac hmac-blake3 --payload-size 16MB \\
        --memlimit auto --parallax on --wrapper on

  Ctrl-C triggers a graceful shutdown: in-flight iterations complete,
  then the partial summary prints."
  (:require [clojure.string :as str]
            [io.github.everanium.itb3.clojure.core :as itb]
            [io.github.everanium.itb3.clojure.loop.payload :as payload]
            [io.github.everanium.itb3.clojure.loop.size :as size]
            [io.github.everanium.itb3.clojure.loop.state :as state]
            [io.github.everanium.itb3.clojure.loop.summary :as summary]
            [io.github.everanium.itb3.clojure.loop.worker :as worker]
            [io.github.everanium.itb3.clojure.runtime :as runtime])
  (:import [java.util.concurrent BrokenBarrierException CountDownLatch CyclicBarrier
            TimeUnit]
           [java.util.concurrent.atomic AtomicBoolean AtomicLong]
           [java.util.concurrent.locks Condition ReentrantLock ReentrantReadWriteLock]))

;; ----------------------------------------------------------------------
;; Flags
;; ----------------------------------------------------------------------

(def ^:private raw-defaults
  "The raw flag values before validation, in the shape the stores
  update."
  {:barrier-fill 0
   :blob-cycle-every 0
   :chunk-size "0"
   :duration "5m"
   :gogc 0
   :gomaxprocs 0
   :goroutines 3
   :hash "areion512"
   :iterations 0
   :json-output false
   :key-bits 0
   :mac "hmac-blake3"
   :memlimit "auto"
   :memprofile ""
   :nonce-bits 0
   :parallax "on"
   :payload-mode "fixed"
   :payload-size "16MB"
   :profile ""
   :rekey-every 0
   :seed 0
   :shape "stream"
   :wrapper "on"})

(defn- store-long
  "A store that accepts a decimal integer into `k`; nil rejects the
  value and the caller prints the parse error."
  [k]
  (fn [raw ^String v]
    (try
      (assoc raw k (Long/parseLong v))
      (catch NumberFormatException _ nil))))

(defn- store-string [k]
  (fn [raw v] (assoc raw k v)))

(defn- default-suffix-num [v]
  (if (zero? (long v)) "" (str " (default " v ")")))

(defn- default-suffix-str [^String v]
  (if (zero? (.length v)) "" (str " (default \"" v "\")")))

(def ^:private flags
  "One command-line flag per entry: its name, the type label the usage
  prints, its help text, whether it takes a value, the default-value
  suffix the usage appends, and the store that parses a value into the
  raw flags. Values are validated after the whole line is parsed. The
  table is in alphabetical order — the order the usage prints."
  [{:name "barrier-fill" :type "int"
    :help "DRBG barrier fill margin: 1 | 2 | 4 | 8 | 16 | 32; 0 = profile default (1)"
    :suffix (default-suffix-num (:barrier-fill raw-defaults))
    :store (store-long :barrier-fill)}
   {:name "blob-cycle-every" :type "int"
    :help (str "reopen each pipeline from its session blob every N iterations per worker; "
               "0 = never")
    :suffix ""
    :store (store-long :blob-cycle-every)}
   {:name "chunk-size" :type "string"
    :help (str "streaming chunk-size budget (e.g. 4MB); 0 = profile default; "
               "inert for pure message shape")
    :suffix (default-suffix-str (:chunk-size raw-defaults))
    :store (store-string :chunk-size)}
   {:name "duration" :type "duration"
    :help "run duration (Go format: 30s / 5m / 1h); ignored when --iterations > 0"
    :suffix (default-suffix-str (:duration raw-defaults))
    :store (store-string :duration)}
   {:name "gogc" :type "int"
    :help "GC trigger percentage; 0 = leave the runtime default"
    :suffix (default-suffix-num (:gogc raw-defaults))
    :store (store-long :gogc)}
   {:name "gomaxprocs" :type "int"
    :help "Go runtime GOMAXPROCS override; 0 = inherit from the environment"
    :suffix (default-suffix-num (:gomaxprocs raw-defaults))
    :store (store-long :gomaxprocs)}
   {:name "goroutines" :type "int"
    :help (str "concurrent workers (1..10); on runtimes without parallelism values above 1 "
               "are clamped to 1")
    :suffix (default-suffix-num (:goroutines raw-defaults))
    :store (store-long :goroutines)}
   {:name "hash" :type "string"
    :help "inner ITB hash primitive name"
    :suffix (default-suffix-str (:hash raw-defaults))
    :store (store-string :hash)}
   {:name "iterations" :type "int"
    :help "fixed per-worker iteration count; 0 = duration-based"
    :suffix ""
    :store (store-long :iterations)}
   {:name "json-output" :type ""
    :help "print the final summary as one compact JSON object instead of log lines"
    :suffix ""
    :bool? true
    :store (fn [raw v]
             (case v
               "true" (assoc raw :json-output true)
               "false" (assoc raw :json-output false)
               nil))}
   {:name "key-bits" :type "int"
    :help "per-seed key width in bits: 512 | 1024 | 2048; 0 = profile default (1024)"
    :suffix (default-suffix-num (:key-bits raw-defaults))
    :store (store-long :key-bits)}
   {:name "mac" :type "string"
    :help "MAC primitive name"
    :suffix (default-suffix-str (:mac raw-defaults))
    :store (store-string :mac)}
   {:name "memlimit" :type "string"
    :help (str "Go heap soft limit: auto (1GiB when goroutines <= 3, else 256MiB, applied only "
               "when the runtime has no limit) or a size (e.g. 512MB)")
    :suffix (default-suffix-str (:memlimit raw-defaults))
    :store (store-string :memlimit)}
   {:name "memprofile" :type "string"
    :help (str "write a Go runtime heap profile (pprof) to this path at the end of the run; "
               "empty = none")
    :suffix (default-suffix-str (:memprofile raw-defaults))
    :store (store-string :memprofile)}
   {:name "nonce-bits" :type "int"
    :help "on-wire nonce width in bits: 128 | 256 | 512; 0 = profile default (512)"
    :suffix (default-suffix-num (:nonce-bits raw-defaults))
    :store (store-long :nonce-bits)}
   {:name "parallax" :type "string"
    :help "parallax layer: on | off"
    :suffix (default-suffix-str (:parallax raw-defaults))
    :store (store-string :parallax)}
   {:name "payload-mode" :type "string"
    :help "plaintext content: fixed | rotating | pattern-zero | pattern-ff | pattern-ascii"
    :suffix (default-suffix-str (:payload-mode raw-defaults))
    :store (store-string :payload-mode)}
   {:name "payload-size" :type "string"
    :help "per-iteration plaintext size (e.g. 1MB / 16MB / 64MB)"
    :suffix (default-suffix-str (:payload-size raw-defaults))
    :store (store-string :payload-size)}
   {:name "profile" :type "string"
    :help (str "exercise this single registered triple profile (overrides --shape with the "
               "profile's surface); empty = shape-based profile pair")
    :suffix (default-suffix-str (:profile raw-defaults))
    :store (store-string :profile)}
   {:name "rekey-every" :type "int"
    :help (str "rotate the parallax + wrapper masters via Rekey every N iterations per worker; "
               "0 = never")
    :suffix ""
    :store (store-long :rekey-every)}
   {:name "seed" :type "uint"
    :help (str "deterministic plaintext RNG seed for bug reproduction, NOT for security testing "
               "(pipeline keys stay CSPRNG-drawn); 0 = crypto/rand plaintexts")
    :suffix ""
    :store (fn [raw ^String v]
             (try
               (assoc raw :seed (Long/parseUnsignedLong v))
               (catch NumberFormatException _ nil)))}
   {:name "shape" :type "string"
    :help "cipher surface to exercise: stream | message | stream_one_shot | both"
    :suffix (default-suffix-str (:shape raw-defaults))
    :store (store-string :shape)}
   {:name "wrapper" :type "string"
    :help "wrapper (Outer cipher) layer: on | off"
    :suffix (default-suffix-str (:wrapper raw-defaults))
    :store (store-string :wrapper)}])

(defn- usage []
  (binding [*out* *err*]
    (println "Usage of loop:")
    (doseq [fl flags]
      (println (if (zero? (.length ^String (:type fl)))
                 (str "  -" (:name fl))
                 (str "  -" (:name fl) " " (:type fl))))
      (println (str "    \t" (:help fl) (:suffix fl))))
    (flush)))

(defn- invalid!
  "Aborts flag resolution with the message the utility prints."
  [msg]
  (throw (ex-info "invalid flags" {::invalid msg})))

(defn- parse-argv
  "Parses argv into the raw flag values. Accepts -name value, --name
  value, -name=value and --name=value; a boolean flag takes no value
  unless given as -name=true / -name=false. Returns the raw map, or
  :help for -h / --help."
  [args]
  (loop [raw raw-defaults
         args (seq args)]
    (if-not args
      raw
      (let [^String arg (first args)]
        (when (or (<= (.length arg) 1) (not= \- (.charAt arg 0)))
          (invalid! (str "unexpected positional arguments: [" arg "]")))
        (let [stripped (if (.startsWith arg "--") (subs arg 2) (subs arg 1))]
          (if (or (= stripped "h") (= stripped "help"))
            :help
            (let [eq (.indexOf ^String stripped (int \=))
                  inline (when (>= eq 0) (subs stripped (inc eq)))
                  name (if (>= eq 0) (subs stripped 0 eq) stripped)
                  fl (first (filter #(= name (:name %)) flags))]
              (when-not fl
                (binding [*out* *err*]
                  (println (str "loop: flag provided but not defined: -" name))
                  (flush))
                (usage)
                (throw (ex-info "invalid flags" {::invalid nil})))
              (let [[value rest-args]
                    (cond
                      inline [inline (next args)]
                      (:bool? fl) ["true" (next args)]
                      :else (let [more (next args)]
                              (when-not more
                                (invalid! (str "flag needs an argument: -" (:name fl))))
                              [(first more) (next more)]))
                    updated ((:store fl) raw value)]
                (when-not updated
                  (invalid! (str "invalid value \"" value "\" for flag -" (:name fl))))
                (recur updated rest-args)))))))))

(defn- hash-registered?
  "Whether name is in the shipped hash registry the binding returns."
  [name]
  (try
    (boolean (some #{name} (itb/hash-names)))
    (catch Exception _ false)))

(defn- profile-surface
  "Resolves a registered profile to the shape family its record's mode
  exposes by reading the record through the binding's lookup: a mode
  beginning with \"streaming\" exposes the stream surfaces, one
  beginning with \"singlemsg\" the message surface, \"blob-only\"
  none."
  [^String name]
  (let [record (try
                 (itb/lookup name)
                 (catch Exception _
                   (invalid! (str "--profile \"" name
                                  "\" is not a registered triple profile"))))
        ^String mode (:mode record)]
    (cond
      (.startsWith mode "streaming") :stream
      (.startsWith mode "singlemsg") :message
      :else (invalid! (str "--profile \"" name
                           "\" carries no cipher surface (blob-only mode)")))))

(defn- narrow-shape
  "Applies a --profile's surface to the requested shape: a
  message-surface profile forces message; a stream-surface profile
  keeps stream or stream_one_shot as requested and turns message or
  both into stream."
  [requested surface]
  (cond
    (= surface :message) :message
    (= requested :stream-one-shot) :stream-one-shot
    :else :stream))

(defn- one-of [allowed v] (some #(= % v) allowed))

(defn- resolve-flags
  "Builds the resolved config from the raw flag values, aborting with
  the validation message of the first failing rule."
  [raw]
  (let [duration-ns (size/parse-duration (:duration raw))
        _ (when (or (nil? duration-ns) (not (pos? (long duration-ns))))
            (invalid! (str "--duration must be positive, got " (:duration raw))))
        _ (when (neg? (long (:iterations raw)))
            (invalid! (str "--iterations must be >= 0, got " (:iterations raw))))
        goroutines (long (:goroutines raw))
        _ (when (or (< goroutines 1) (> goroutines (long state/max-workers)))
            (invalid! (str "--goroutines must be in 1.." state/max-workers
                           ", got " goroutines)))
        ;; Concurrency mode. This binding runs shared-handle: JVM
        ;; platform threads call into one Pipeline handle concurrently.
        ;; The Clojure Pipeline is an immutable record holding one Java
        ;; Pipeline, which is itself a long over an opaque Go-side
        ;; registry key; the record adds no mutable state of its own,
        ;; every entry the handle is passed to is re-entrant after
        ;; construction, and the one piece of mutable machinery behind
        ;; it — the Java layer's pooled direct scratch pair — is taken
        ;; with an atomic swap so a concurrent caller falls back to
        ;; fresh buffers instead of sharing. So --goroutines is the
        ;; thread count verbatim, never clamped.
        workers goroutines
        shape (or (worker/parse-shape (:shape raw))
                  (invalid! (str "--shape must be stream | message | stream_one_shot | both, "
                                 "got \"" (:shape raw) "\"")))
        _ (when-not (hash-registered? (:hash raw))
            (invalid! (str "--hash \"" (:hash raw) "\" is not a registered hash primitive")))
        ;; --mac is validated by Init: the C ABI enumerates no MAC
        ;; names, so an unknown one surfaces as a construction failure.
        payload (or (size/parse-size (:payload-size raw))
                    (invalid! (str "--payload-size: invalid size \""
                                   (:payload-size raw) "\"")))
        _ (when (< (long payload) 1)
            (invalid! "--payload-size must be at least 1 byte"))
        memlimit-auto (= "auto" (:memlimit raw))
        memlimit (if memlimit-auto
                   (if (<= workers 3) (bit-shift-left 1 30) (bit-shift-left 256 20))
                   (or (size/parse-size (:memlimit raw))
                       (invalid! (str "--memlimit: invalid size \"" (:memlimit raw) "\""))))
        _ (when (neg? (long (:gogc raw)))
            (invalid! (str "--gogc must be >= 0, got " (:gogc raw))))
        parallax (case (:parallax raw)
                   "on" true
                   "off" false
                   (invalid! (str "--parallax must be on | off, got \"" (:parallax raw) "\"")))
        wrapper (case (:wrapper raw)
                  "on" true
                  "off" false
                  (invalid! (str "--wrapper must be on | off, got \"" (:wrapper raw) "\"")))
        shape (if (zero? (.length ^String (:profile raw)))
                shape
                (narrow-shape shape (profile-surface (:profile raw))))
        _ (when-not (one-of [0 512 1024 2048] (:key-bits raw))
            (invalid! (str "--key-bits must be 512 | 1024 | 2048 (or 0 = profile default), got "
                           (:key-bits raw))))
        _ (when-not (one-of [0 128 256 512] (:nonce-bits raw))
            (invalid! (str "--nonce-bits must be 128 | 256 | 512 (or 0 = profile default), got "
                           (:nonce-bits raw))))
        _ (when-not (one-of [0 1 2 4 8 16 32] (:barrier-fill raw))
            (invalid! (str "--barrier-fill must be 1 | 2 | 4 | 8 | 16 | 32 "
                           "(or 0 = profile default), got " (:barrier-fill raw))))
        chunk-size (or (size/parse-size (:chunk-size raw))
                       (invalid! (str "--chunk-size: invalid size \"" (:chunk-size raw) "\"")))
        _ (when (neg? (long (:gomaxprocs raw)))
            (invalid! (str "--gomaxprocs must be > 0 when specified, got " (:gomaxprocs raw))))
        _ (when (neg? (long (:rekey-every raw)))
            (invalid! (str "--rekey-every must be >= 0, got " (:rekey-every raw))))
        _ (when (neg? (long (:blob-cycle-every raw)))
            (invalid! (str "--blob-cycle-every must be >= 0, got " (:blob-cycle-every raw))))
        payload-mode (or (payload/parse-mode (:payload-mode raw))
                         (invalid! (str "--payload-mode must be fixed | rotating | pattern-zero "
                                        "| pattern-ff | pattern-ascii, got \""
                                        (:payload-mode raw) "\"")))]
    {:duration-ns (long duration-ns)
     :iterations (:iterations raw)
     :workers-requested workers
     :workers workers
     :shape shape
     :hash (:hash raw)
     :mac (:mac raw)
     :payload (long payload)
     :memlimit (long memlimit)
     :memlimit-auto memlimit-auto
     :gogc (:gogc raw)
     :parallax parallax
     :wrapper wrapper
     :profile (:profile raw)
     :key-bits (:key-bits raw)
     :nonce-bits (:nonce-bits raw)
     :chunk-size (long chunk-size)
     :barrier-fill (:barrier-fill raw)
     :gomaxprocs (:gomaxprocs raw)
     :rekey-every (:rekey-every raw)
     :blob-cycle-every (:blob-cycle-every raw)
     :payload-mode payload-mode
     :seed (:seed raw)
     :json-output (:json-output raw)
     :memprofile (:memprofile raw)}))

(defn- parse-flags
  "Resolves argv into a config, or into an exit code with the message
  already printed: 0 for help, 2 for the first failing rule."
  [args]
  (try
    (let [raw (parse-argv args)]
      (if (= raw :help)
        (do (usage) {:code 0})
        {:cfg (resolve-flags raw) :code 0}))
    (catch clojure.lang.ExceptionInfo e
      (let [data (ex-data e)]
        (if-not (contains? data ::invalid)
          (throw e)
          (do
            (when-let [msg (::invalid data)]
              (state/err-line (str "loop: " msg)))
            {:code 2}))))))

;; ----------------------------------------------------------------------
;; Signals
;; ----------------------------------------------------------------------

(def ^:private ^AtomicBoolean signal-seen (AtomicBoolean.))

(def ^:private ^CountDownLatch summary-done
  "Counted down once the summary has been emitted, so the shutdown
  hook can hold the JVM's own termination back until then."
  (CountDownLatch. 1))

(defn- install-signals
  "Graceful stop. SIGINT / SIGTERM set a flag the main thread polls
  while it waits for the workers; it turns the flag into the stop
  request every worker checks before starting an iteration, so a
  signal interrupts nothing mid-call — the in-flight encrypt / decrypt
  / compare completes, the worker returns, and the partial summary
  prints with the verdict the completed iterations earned.

  Clojure-specific: the supported way to observe a termination signal
  on this runtime is a shutdown hook, which runs concurrently with the
  main thread rather than in place of it and cannot set the exit code,
  so the hook only raises the flag and then blocks until the summary
  is out; the verdict's code is then delivered by halting the runtime
  from the main thread, which is also what makes the exit code the
  verdict's rather than the JVM's own signal code."
  []
  (.addShutdownHook (java.lang.Runtime/getRuntime)
                    (Thread. ^Runnable
                             (fn []
                               (.set signal-seen true)
                               (try
                                 (.await summary-done 2 TimeUnit/MINUTES)
                                 (catch InterruptedException _
                                   (.interrupt (Thread/currentThread)))))
                             "loop-signal")))

;; ----------------------------------------------------------------------
;; Pipelines
;; ----------------------------------------------------------------------

(defn- fill-keystream-layers
  "Supplies the keystream-capable primitive for every layer the
  profile record leaves unnamed and the run engages: a missing
  parallax palette becomes three copies of the fill cipher (with the
  library's default segment size when the record carries none), a
  missing outer cipher becomes the fill cipher. These are opts
  overrides that fold into the resolved record the blob carries — a
  derived profile is never registered, so no name the receiver did not
  agree to reaches the wire. Returns the opts map and whether a layer
  was filled."
  [^String name opts want-parallax want-wrapper]
  (let [record (try
                 (itb/lookup name)
                 (catch Exception _
                   (invalid! (str "--profile \"" name
                                  "\" is not a registered triple profile"))))
        palette-missing (and want-parallax (empty? (:palette record)))
        outer-missing (and want-wrapper (zero? (.length ^String (:outer record))))]
    [(cond-> opts
       palette-missing (assoc :parallax-palette (repeat 3 state/keystream-fill-cipher))
       ;; A recipe that never carried a palette never carried a segment
       ;; size either, and the schedule rejects zero.
       (and palette-missing (zero? (long (:segment record))))
       (assoc :parallax-segment-size state/keystream-fill-segment)
       outer-missing (assoc :outer-cipher state/keystream-fill-cipher))
     (or palette-missing outer-missing)]))

(defn- dash ^String [^String s]
  (if (zero? (.length s)) "-" s))

(defn- log-pipeline-initialised
  "Prints the construction line with the recipe read back from the
  blob the Pipeline handed out, not echoed from the flags: every
  construction override is proven to have reached the library by the
  value the receiver would see. Record values that are empty (a No MAC
  profile's MAC, a mixed profile's single hash) print as \"-\"."
  [^String profile ^bytes blob]
  (let [record (try
                 (itb/inspect blob)
                 (catch Exception e
                   (state/log-line (str "pipeline initialised: profile=" profile
                                        " blob=" (alength blob) " bytes (inspect: "
                                        (state/detail e) ")"))
                   nil))]
    (when record
      (state/log-line (str "pipeline initialised: profile=" profile
                           " blob=" (alength blob) " bytes"
                           " hash=" (dash (:hash record))
                           " key-bits=" (:key-bits record)
                           " nonce-bits=" (or (:nonce-bits record) 0)
                           " barrier-fill=" (or (:barrier-fill record) 0)
                           " chunk-size=" (:chunk record)
                           " mac=" (dash (:mac record))
                           " parallax=" (state/on-off (:parallax? record))
                           " wrapper=" (state/on-off (:wrapper? record)))))))

(defn- build-pipeline
  "Constructs one Pipeline against profile with every flag-carried
  override in the opts string (zero values included — the shared
  library treats zero as \"profile default\"), then obtains the Init
  blob once through save: the binding's init entry does not hand the
  blob back, and the bytes are the ones Init produced. Later blob
  reopens use the retained blob; save is never called again. Nil after
  printing the construction failure."
  [cfg ^String profile]
  (let [base {:inner-hash (:hash cfg)
              :mac-name (:mac cfg)
              :parallax? (:parallax cfg)
              :wrapper? (:wrapper cfg)
              :key-bits (:key-bits cfg)
              :nonce-bits (:nonce-bits cfg)
              :barrier-fill (:barrier-fill cfg)
              :chunk-size (:chunk-size cfg)}
        opts (if (zero? (.length ^String (:profile cfg)))
               base
               (let [[filled-opts filled?] (fill-keystream-layers
                                            (:profile cfg) base
                                            (:parallax cfg) (:wrapper cfg))]
                 (when filled?
                   (state/err-line (str "loop: " (:profile cfg)
                                        " leaves the requested keystream layers unnamed; "
                                        state/keystream-fill-cipher " supplied for them")))
                 filled-opts))
        pipe (try
               (itb/init profile opts)
               (catch Exception e
                 (state/err-line (str "loop: Init(" profile "): " (state/detail e)))
                 nil))]
    (when pipe
      (let [blob (try
                   (itb/save pipe)
                   (catch Exception e
                     (state/err-line (str "loop: Save(" profile "): " (state/detail e)))
                     (.close ^java.lang.AutoCloseable pipe)
                     nil))]
        (when blob
          (log-pipeline-initialised profile blob)
          {:pipe pipe :blob blob})))))

;; ----------------------------------------------------------------------
;; Run
;; ----------------------------------------------------------------------

(defn- shape-thread-name ^String [^long id]
  (str "loop-worker-" id))

(defn- shape-runtime!
  "Runtime shaping. A long run under allocation churn grows the Go
  heap inside the shared library without bound unless a soft limit
  paces the collector, so a limit is always in force: an explicit
  --memlimit is set as given, and auto caps the heap only when the
  runtime reports no limit at all (a limit already installed from the
  environment is left standing). The GC percentage and GOMAXPROCS are
  set only when their flag is non-zero — a zero flag skips the setter
  rather than calling it with zero, because zero is a real value to
  the GC-percent setter, and a call would clobber whatever the
  environment installed. All of it lands before any Pipeline exists so
  the baselines are taken under the shaped runtime. Returns the
  effective heap limit."
  [cfg]
  (if (:memlimit-auto cfg)
    (when (= Long/MAX_VALUE (runtime/set-memory-limit! -1))
      (runtime/set-memory-limit! (long (:memlimit cfg))))
    (runtime/set-memory-limit! (long (:memlimit cfg))))
  (when (pos? (long (:gogc cfg)))
    (runtime/set-gc-percent! (:gogc cfg)))
  (when (pos? (long (:gomaxprocs cfg)))
    (runtime/set-gomaxprocs! (:gomaxprocs cfg)))
  (runtime/set-memory-limit! -1))

(defn- log-startup [cfg]
  (state/log-line (str "start: duration=" (size/human-duration (:duration-ns cfg))
                       " iterations=" (:iterations cfg)
                       " goroutines=" (:workers-requested cfg)
                       " workers=" (:workers cfg)
                       " concurrency=" state/concurrency
                       " shape=" (worker/shape-label (:shape cfg))
                       " hash=" (:hash cfg)
                       " mac=" (:mac cfg)
                       " payload=" (size/human-bytes (:payload cfg))
                       " memlimit=" (size/human-bytes (:memlimit cfg))
                       " parallax=" (state/on-off (:parallax cfg))
                       " wrapper=" (state/on-off (:wrapper cfg))))
  (state/log-line (str "overrides: profile=\"" (:profile cfg) "\""
                       " key-bits=" (:key-bits cfg)
                       " nonce-bits=" (:nonce-bits cfg)
                       " chunk-size=" (size/human-bytes (:chunk-size cfg))
                       " barrier-fill=" (:barrier-fill cfg)
                       " gomaxprocs=" (:gomaxprocs cfg)
                       " rekey-every=" (:rekey-every cfg)
                       " blob-cycle-every=" (:blob-cycle-every cfg)
                       " payload-mode=" (payload/mode-label (:payload-mode cfg))
                       " seed=" (Long/toUnsignedString (long (:seed cfg)))
                       " json-output=" (if (:json-output cfg) "true" "false")))
  (state/log-line (str "policy: microbatch-tiers=" (state/policy-label "ITB_MICROBATCH_TIERS")
                       " hashpool-starters=" (state/policy-label "ITB_HASHPOOL_STARTERS"))))

(defn- make-worker-state
  "Allocation posture. Per-worker plaintexts are allocated once and
  held for the whole run (rotating mode refills them in place per
  iteration); the pump accumulators and the drain scratch live inside
  each worker and are reused across iterations; the message and
  one-shot outputs are allocated by the binding per call and reclaimed
  per iteration. Under the default fixed CSPRNG mode every worker's
  buffer is distinct, so cross-worker data crossover is detectable;
  pattern modes trade that property for content edge-case coverage."
  [cfg ^long id]
  (let [seeded? (not (zero? (long (:seed cfg))))
        rng (payload/seed-worker (:seed cfg) id)
        plaintext (byte-array (long (:payload cfg)))]
    (when-not (payload/fill-payload (:payload-mode cfg) seeded? rng plaintext)
      (invalid! "payload fill: csprng"))
    {:id id
     :plaintext plaintext
     :payload-mode (:payload-mode cfg)
     :seeded? seeded?
     :rng rng
     :scratch (byte-array (long state/pump-slice))
     :wire (state/make-acc state/pump-slice)
     :plain (state/make-acc state/pump-slice)}))

(defn- await-workers
  "Waits for every worker, polling every 100 ms so the duration
  deadline and a signal are both noticed promptly. Returns the instant
  the last worker returned."
  [r ^long start]
  (let [cfg (:cfg r)
        ^ReentrantLock lock (:done-lock r)]
    (.lock lock)
    (try
      (while (pos? (long @(:active r)))
        (when (or (.get signal-seen)
                  (and (zero? (long (:iterations cfg)))
                       (>= (- (System/nanoTime) start) (long (:duration-ns cfg)))))
          (state/request-stop! r))
        (try
          (.await ^Condition (:done-cond r) 100 TimeUnit/MILLISECONDS)
          (catch InterruptedException _
            (.interrupt (Thread/currentThread))
            (state/request-stop! r))))
      (let [finish (long @(:finish-nanos r))]
        (if (zero? finish) start finish))
      (finally
        (.unlock lock)))))

(defn- run
  "Drives the five phases — startup, warmup, main loop, shutdown,
  summary — and returns the process exit code."
  [args]
  (let [parsed (parse-flags args)
        cfg (:cfg parsed)]
    (if-not cfg
      (long (:code parsed))
      (let [cfg (assoc cfg :memlimit (shape-runtime! cfg))
            _ (log-startup cfg)
            ;; Pipeline construction — one shared handle per exercised
            ;; shape. stream and stream_one_shot share the streaming
            ;; handle.
            stream-profile (if (zero? (.length ^String (:profile cfg)))
                             state/default-stream-profile
                             (:profile cfg))
            msg-profile (if (zero? (.length ^String (:profile cfg)))
                          state/default-message-profile
                          (:profile cfg))
            shape (:shape cfg)
            built-stream (when (contains? #{:stream :stream-one-shot :both} shape)
                           (build-pipeline cfg stream-profile))
            built-msg (when (and (or (not (contains? #{:stream :stream-one-shot :both} shape))
                                     built-stream)
                                 (contains? #{:message :both} shape))
                        (build-pipeline cfg msg-profile))]
        (if (or (and (contains? #{:stream :stream-one-shot :both} shape) (nil? built-stream))
                (and (contains? #{:message :both} shape) (nil? built-msg)))
          1
          (let [workers (long (:workers cfg))]
            (if (> (long (:payload cfg)) (- Integer/MAX_VALUE 8))
              (do (state/err-line "loop: --payload-size exceeds the largest JVM array") 1)
              (let [states (mapv #(make-worker-state cfg %) (range workers))
                    done-lock (ReentrantLock.)
                    r {:cfg cfg
                       :stream-profile stream-profile
                       :msg-profile msg-profile
                       :pipes (atom {:stream (:pipe built-stream)
                                     :msg (:pipe built-msg)
                                     :stream-blob (or (:blob built-stream) (byte-array 0))
                                     :msg-blob (or (:blob built-msg) (byte-array 0))})
                       :counters (vec (repeatedly workers state/make-counters))
                       :warmup-done (CyclicBarrier. (inc workers))
                       :release (CyclicBarrier. (inc workers))
                       :active (atom workers)
                       ;; Handle mutation. Iterations hold the read side
                       ;; for their whole encrypt → decrypt → compare;
                       ;; rekey and blob reopen take the write side, so
                       ;; no cipher call is in flight while a handle's
                       ;; keying changes or the handle itself is
                       ;; swapped, and no encrypt is separated from its
                       ;; decrypt by either.
                       :pipes-lock (ReentrantReadWriteLock.)
                       :rekeys (AtomicLong.)
                       :blob-cycles (AtomicLong.)
                       :stop (AtomicBoolean.)
                       :done-lock done-lock
                       :done-cond (.newCondition done-lock)
                       :finish-nanos (atom 0)}]
                (install-signals)
                ;; Warmup barrier. Every worker runs one iteration and
                ;; waits; the clock starts only once all of them have
                ;; paid their first-call costs (pool warm-up, lazy
                ;; kernel dispatch, page faults on the payload buffers,
                ;; and on this runtime the tiered JIT's first pass over
                ;; the iteration body), and the RSS and pool baselines
                ;; taken here describe a process that has already run
                ;; the whole cipher path once per worker.
                (let [warmup-start (System/nanoTime)
                      threads (mapv (fn [w]
                                      (doto (Thread. ^Runnable (fn [] (worker/run-worker r w))
                                                     ^String (shape-thread-name (:id w)))
                                        (.setDaemon false)
                                        (.start)))
                                    states)]
                  (try
                    (.await ^CyclicBarrier (:warmup-done r))
                    (catch InterruptedException e
                      (.interrupt (Thread/currentThread))
                      (state/err-line (str "loop: warmup barrier: " e)))
                    (catch BrokenBarrierException e
                      (state/err-line (str "loop: warmup barrier: " e))))
                  (let [[rss-warmup _] (summary/read-rss)
                        pool-warmup (summary/pool-snapshot)]
                    (state/log-line
                     (str "warmup: " workers " workers x 1 iter completed in "
                          (size/human-duration
                           (size/round-to (- (System/nanoTime) warmup-start) 100000000))
                          " (baseline rss=" (size/human-bytes rss-warmup) ")"))
                    ;; Open the gate; the duration is a deadline the
                    ;; waiter below enforces in duration mode.
                    (let [start (System/nanoTime)]
                      (try
                        (.await ^CyclicBarrier (:release r))
                        (catch InterruptedException e
                          (.interrupt (Thread/currentThread))
                          (state/err-line (str "loop: release barrier: " e)))
                        (catch BrokenBarrierException e
                          (state/err-line (str "loop: release barrier: " e))))
                      (let [finish (await-workers r start)
                            elapsed-ns (- finish start)
                            [rss-final rss-peak] (summary/read-rss)
                            pool-steady (summary/pool-snapshot)]
                        (doseq [^Thread t threads]
                          (try
                            (.join t)
                            (catch InterruptedException _
                              (.interrupt (Thread/currentThread)))))
                        (when-not (zero? (.length ^String (:memprofile cfg)))
                          (try
                            (runtime/write-heap-profile! (:memprofile cfg))
                            (state/log-line (str "memprofile: heap profile written to "
                                                 (:memprofile cfg)))
                            (catch Exception e
                              (state/err-line (str "loop: memprofile: " (state/detail e))))))
                        (let [exit (summary/emit-summary
                                    r elapsed-ns
                                    {:rss-warmup rss-warmup
                                     :rss-peak rss-peak
                                     :rss-final rss-final
                                     :pool-warmup pool-warmup
                                     :pool-steady pool-steady})
                              pipes @(:pipes r)]
                          (some-> ^java.lang.AutoCloseable (:stream pipes) .close)
                          (some-> ^java.lang.AutoCloseable (:msg pipes) .close)
                          exit)))))))))))))

;; Restores the default disposition of SIGPIPE.
;;
;; Clojure-specific. The runtime ignores the signal and the standard
;; streams swallow the write error that replaces it, so a consumer that
;; stops reading leaves the process printing into nothing and exiting 0
;; with its verdict undelivered. With the default disposition back the
;; first such write ends the process, which is what every other
;; implementation does and what a fleet driver expects.
(defn- restore-sigpipe []
  (sun.misc.Signal/handle (sun.misc.Signal. "PIPE") sun.misc.SignalHandler/SIG_DFL))

(defn -main
  "Entry point."
  [& args]
  (restore-sigpipe)
  (let [code (try
               (run args)
               (catch clojure.lang.ExceptionInfo e
                 (if-let [msg (::invalid (ex-data e))]
                   (do (state/err-line (str "loop: " msg)) 1)
                   (throw e))))]
    (flush)
    (.countDown summary-done)
    ;; Clojure-specific. The verdict's code is delivered by halting the
    ;; runtime rather than by returning from main: when a signal has
    ;; started the shutdown sequence, returning would let the JVM
    ;; finish that sequence with its own signal-derived code instead of
    ;; this one, and the agent thread pools behind clojure.core would
    ;; keep the process alive for a minute after the summary is out.
    (.halt (java.lang.Runtime/getRuntime) (int code))))
