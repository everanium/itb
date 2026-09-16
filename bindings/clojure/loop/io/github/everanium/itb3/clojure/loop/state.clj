(ns io.github.everanium.itb3.clojure.loop.state
  "Declarations every other unit of the utility shares: the run-wide
  constants, the log and error printers, the growable output
  accumulator, the per-worker counters, the run state the workers
  hammer in parallel, and the rendering of a binding error.

  Clojure-specific. This unit exists because a namespace cannot
  require a namespace that requires it back: the maintenance
  operations and the worker body both record worker errors and both
  are reached from the entry unit, which is a cycle the moment those
  declarations live with the entry point. They live here instead, and
  every other unit requires this one."
  (:require [clojure.string :as str]
            [io.github.everanium.itb3.clojure.error :as err])
  (:import [java.util.concurrent.atomic AtomicBoolean AtomicLong]))

(def max-workers
  "--goroutines ceiling; the harness targets modest hosts and each
  worker pins payload-sized buffers for the whole run."
  10)

(def concurrency
  "The concurrency mode this binding implements, as the summary
  reports it (shared-handle / independent-handles / single)."
  "shared-handle")

(def pump-slice
  "Largest slice fed to a stream session per write; the drain after
  every write uses the same bound."
  (bit-shift-left 1 20))

(def default-stream-profile
  "The streaming profile the shape-based pair is built against when
  --profile is empty."
  "streaming-aead-triple-mac-v1")

(def default-message-profile
  "The Single Message profile of the same pair."
  "singlemsg-triple-mac-v1")

(def keystream-fill-cipher
  "The keystream-capable primitive supplied for a layer a profile
  leaves unnamed: PRF-grade, so sound outside the barrier, and the
  closest relative of the AES-based inner primitive whose profiles
  need the fill."
  "aescmac")

(def keystream-fill-segment
  "The parallax segment size a filled palette runs with — the
  library's own default; a schedule rejects zero."
  4093)

(defn log-line
  "Prints one prefixed status line to stdout. Clojure-specific: the
  text and its newline go out in a single write rather than through
  println, which takes them as two. Workers log concurrently during
  maintenance, and between println's two writes another worker's line
  lands whole, joining two texts and trailing both newlines."
  [line]
  (let [^java.io.Writer w *out*]
    (.write w (str "[loop] " line "\n"))
    (.flush w)))

(defn err-line
  "Prints one prefixed diagnostic to stderr, in a single write for the
  same reason as log-line."
  [line]
  (let [^java.io.Writer w *err*]
    (.write w (str line "\n"))
    (.flush w)))

(defn on-off ^String [b] (if b "on" "off"))

(defn policy-label
  "Renders an encoder policy env value for the summary: the raw string
  when set, \"default\" when the shipped ladder applies."
  ^String [^String name]
  (let [v (System/getenv name)]
    (if (or (nil? v) (zero? (.length (.trim ^String v))))
      "default"
      (str/triml v))))

;; ----------------------------------------------------------------------
;; Output accumulator
;; ----------------------------------------------------------------------

(definterface IAcc
  (accReset [])
  (accAppend [^bytes src ^long n])
  (^"[B" accRaw [])
  (^long accLen []))

(deftype Acc [^{:tag "[B" :unsynchronized-mutable true} buf
              ^{:tag long :unsynchronized-mutable true} len]
  IAcc
  (accReset [_] (set! len 0) nil)
  (accAppend [_ src n]
    (let [need (+ len n)]
      (when (> need (alength ^bytes buf))
        (let [cap (loop [c (max 1024 (* 2 (alength ^bytes buf)))]
                    (if (>= c need) c (recur (* 2 c))))
              grown (byte-array cap)]
          (System/arraycopy buf 0 grown 0 (int len))
          (set! buf grown)))
      (System/arraycopy src 0 buf (int len) (int n))
      (set! len need)
      nil))
  (accRaw [_] buf)
  (accLen [_] len))

(defn make-acc
  "A growable output accumulator whose backing array the comparison
  reads without a copy: the round-trip buffers are megabytes, and a
  copy per drain would dominate the very allocation behaviour the run
  is measuring."
  ^Acc [^long cap]
  (Acc. (byte-array cap) 0))

;; ----------------------------------------------------------------------
;; Counters and run state
;; ----------------------------------------------------------------------

(defn make-counters
  "One worker's counters, read by the summary after every worker has
  returned, and the error it stopped on."
  []
  {:iters (AtomicLong.)
   :bytes-enc (AtomicLong.)
   :bytes-dec (AtomicLong.)
   :nanos-enc (AtomicLong.)
   :nanos-dec (AtomicLong.)
   :error (atom nil)})

(defn add-encrypt! [c ^long nanos]
  (.addAndGet ^AtomicLong (:nanos-enc c) nanos))

(defn add-decrypt! [c ^long nanos]
  (.addAndGet ^AtomicLong (:nanos-dec c) nanos))

(defn add-iteration! [c ^long enc-bytes ^long dec-bytes]
  (.incrementAndGet ^AtomicLong (:iters c))
  (.addAndGet ^AtomicLong (:bytes-enc c) enc-bytes)
  (.addAndGet ^AtomicLong (:bytes-dec c) dec-bytes))

(defn counter-value ^long [c k]
  (.get ^AtomicLong (k c)))

(defn stop-requested? [r]
  (.get ^AtomicBoolean (:stop r)))

(defn request-stop! [r]
  (.set ^AtomicBoolean (:stop r) true))

(defn fail
  "Records the worker's error text (first error wins) and requests a
  stop of the whole run."
  [r ^long id text]
  (swap! (:error (nth (:counters r) id)) #(or % text))
  (request-stop! r)
  false)

;; ----------------------------------------------------------------------
;; Error rendering
;; ----------------------------------------------------------------------

(def ^:private detail-re
  "Pattern the binding's error message carries: the status code and,
  behind it, the library's own diagnostic sentence."
  #"(?s)^itb: status=(-?\d+)(?:: (.*))?$")

(defn detail
  "Renders a binding error the way every implementation reports a
  failed library call: `status <code>: <last error>`; any other
  failure carries its own text. No wording of a status code is
  composed here — the library's diagnostic already opens with the
  class of failure and, where there is one, the specific case, so it
  is printed as it arrived.

  Clojure-specific. The binding's status keywords are a type-system
  enumeration with no human text of their own, and the diagnostic is
  folded into the ex-info message behind a fixed prefix, so the
  message is where it is recovered from."
  ^String [^Throwable e]
  (let [message (.getMessage e)]
    (cond
      (nil? message) (.toString e)
      (not (err/itb-error? e)) message
      :else (let [m (re-find detail-re message)]
              (if m
                (str "status " (nth m 1) ": " (or (nth m 2) ""))
                message)))))
