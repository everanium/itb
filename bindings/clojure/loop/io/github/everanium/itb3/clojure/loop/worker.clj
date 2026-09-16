(ns io.github.everanium.itb3.clojure.loop.worker
  "The worker: its thread body (one warmup iteration, the warmup
  barrier, the main loop), one iteration, the session pump loop the
  stream shape drives, and the round-trip comparison that decides
  between a worker error and a data mismatch."
  (:require [io.github.everanium.itb3.clojure.core :as itb]
            [io.github.everanium.itb3.clojure.loop.ops :as ops]
            [io.github.everanium.itb3.clojure.loop.payload :as payload]
            [io.github.everanium.itb3.clojure.loop.state :as state]
            [io.github.everanium.itb3.clojure.stream :as stream])
  (:import [io.github.everanium.itb3.clojure.loop.state Acc]
           [java.util Arrays]
           [java.util.concurrent BrokenBarrierException CyclicBarrier]
           [java.util.concurrent.locks Lock ReentrantLock ReentrantReadWriteLock]))

(def shapes
  "Cipher surfaces the --shape flag selects, keyed by the flag
  spelling: a session pump (begin / write / read / end), one
  whole-buffer Single Message call, one whole-buffer call on the
  stream surface, and all three rotating by iteration number."
  {"stream" :stream
   "message" :message
   "stream_one_shot" :stream-one-shot
   "both" :both})

(def shape-label
  "The flag spelling of a shape keyword."
  (into {} (map (fn [[label kw]] [kw label])) shapes))

(defn parse-shape [s] (get shapes s))

(defmacro ^:private stage
  "Runs body, tagging any failure with the session entry that raised
  it so the pump loop can name the failing call.

  Clojure-specific. The session surface signals failure by throwing,
  so the tag travels on an ex-info the pump unwraps rather than on a
  returned result record."
  [what & body]
  `(try
     ~@body
     (catch Exception e#
       (throw (ex-info "pump" {::fail {:what ~what :err e#}})))))

(defn- pump
  "Pump loop. The Go harness hands ITB an io.Reader / io.Writer pair
  and ITB drives the chunk loop internally; the C ABI has no reader /
  writer entry, so the caller drives it: open a session, feed slices
  of at most 1 MiB, drain whatever the session has produced after
  every write (a read before end never blocks), end, then drain until
  the session reports finished (after end, a read on an empty spool
  blocks until the terminal bytes arrive). The whole produced output
  lands in the worker's reusable accumulator. The loop is written here
  rather than delegated to the binding's pump convenience so it stands
  in the utility, at the same place, in every language. On failure the
  result names the failing call and carries its error."
  [pipe encrypt? ^bytes src src-len ^Acc acc ^bytes scratch]
  (.accReset acc)
  (try
    ;; Clojure-specific. Both session directions satisfy one protocol
    ;; on the binding's surface, so the loop below is written once and
    ;; the direction is decided only at the open.
    (let [session (stage "StreamBegin"
                         (if encrypt? (itb/encrypt-stream pipe) (itb/decrypt-stream pipe)))]
      (try
        (loop [off 0]
          (when (< off (long src-len))
            (let [n (min (long state/pump-slice) (- (long src-len) off))]
              (stage "StreamWrite" (stream/write! session src off n))
              (loop []
                (let [m (long (:count (stage "StreamRead" (stream/read! session scratch))))]
                  (when (pos? m)
                    (.accAppend acc scratch m)
                    (recur))))
              (recur (+ off (long state/pump-slice))))))
        (stage "StreamEnd" (stream/end! session))
        (loop []
          (let [res (stage "StreamRead" (stream/read! session scratch))]
            (.accAppend acc scratch (long (:count res)))
            (when-not (:finished? res)
              (recur))))
        nil
        (finally
          (.close ^java.lang.AutoCloseable session))))
    (catch clojure.lang.ExceptionInfo e
      (or (::fail (ex-data e)) (throw e)))))

(defn- first-difference
  "First offset at which the two ranges differ; the shorter length
  when one is a prefix of the other."
  ^long [^bytes a ^long a-len ^bytes b ^long b-len]
  (let [n (min a-len b-len)]
    (loop [i 0]
      (cond
        (>= i n) n
        (not= (aget a i) (aget b i)) i
        :else (recur (inc i))))))

(defn- hex-window
  "Up to 16 bytes of buf from off as lowercase hex, or \"-\" when buf
  has no bytes there."
  ^String [^bytes buf ^long len ^long off]
  (if (>= off len)
    "-"
    (let [n (min 16 (- len off))
          sb (StringBuilder. (int (* 2 n)))]
      (dotimes [i n]
        (let [v (bit-and (int (aget buf (+ off i))) 0xFF)]
          (.append sb (Character/forDigit (unsigned-bit-shift-right v 4) 16))
          (.append sb (Character/forDigit (bit-and v 0xF) 16))))
      (.toString sb))))

(defn- cipher-fail
  "Records a worker error for a failed cipher call."
  [r id iter shape direction what ^Throwable e]
  (let [head (str "g" id " iter " iter " shape=" (shape-label shape) ": " direction)]
    (state/fail r id
                (if (nil? what)
                  (str head ": " (state/detail e))
                  (str head ": " what ": " (state/detail e))))))

(defn- select-shape
  "Shape dispatch. message is one whole-buffer call on the Single
  Message Pipeline; stream_one_shot is one whole-buffer call on the
  streaming Pipeline (the C ABI's whole-plaintext stream entry, which
  routes to the same whole-buffer stream method the Go harness calls
  by name); stream opens a session on that same streaming Pipeline and
  drives the chunk loop from the utility. Under both the three rotate
  by iteration number so the session path and the whole-buffer path
  alternate on one handle inside every worker — the cross-path
  state-reuse hazard this harness exists to catch."
  [shape ^long iter]
  (if (not= shape :both)
    shape
    (case (rem iter 3)
      0 :stream
      1 :message
      :stream-one-shot)))

(defn- report-mismatch
  "Failure model. A cipher call that returns a non-OK status is a
  worker error: it is recorded, the run is asked to stop, the other
  workers finish their in-flight iteration, and the error is listed in
  the summary with the FAIL verdict. A round-trip that returns OK with
  different bytes is a data mismatch: the process terminates here,
  without summary or cleanup, because the Pipeline state that produced
  the wrong bytes is the evidence and nothing that runs afterwards may
  touch it. Clojure-specific: halting the runtime is the exit that
  runs neither the shutdown hooks nor the Cleaner registrations behind
  the Java layer's handles, which is the point — a cleaner-driven free
  would release the very state the operator is meant to inspect."
  [id iter shape ^bytes want want-len ^bytes got got-len]
  (let [want-len (long want-len)
        got-len (long got-len)
        off (first-difference want want-len got got-len)]
    (state/err-line
     (str "loop: DATA MISMATCH g" id " iter " iter " shape=" (shape-label shape)
          ": want " want-len " bytes, got " got-len " bytes, "
          "first difference at offset " off ": "
          "want " (hex-window want want-len off)
          " got " (hex-window got got-len off)))
    (flush)
    (.halt (java.lang.Runtime/getRuntime) 3)))

(defn- run-iteration
  "One iteration. In order: refill the plaintext under rotating mode;
  take the read lock; pick the surface; encrypt (timed); decrypt
  (timed); compare the round-trip with the plaintext; bump the
  counters; release the lock. The whole round-trip runs under the read
  lock so handle-mutating maintenance (rekey, blob reopen) never lands
  between an encrypt and its matching decrypt — maintenance runs after
  this returns, from the worker loop. False after recording a worker
  error."
  [r w ^long iter]
  (let [id (long (:id w))
        c (nth (:counters r) id)
        ^bytes plaintext (:plaintext w)]
    (if (and (= :rotating (:payload-mode w))
             (not (payload/fill-payload :rotating (:seeded? w) (:rng w) plaintext)))
      (state/fail r id (str "g" id " iter " iter ": payload refill: csprng"))
      (let [^Lock lock (.readLock ^ReentrantReadWriteLock (:pipes-lock r))]
        (.lock lock)
        (try
          (let [shape (select-shape (:shape (:cfg r)) iter)
                pipes @(:pipes r)
                ^Acc wire-acc (:wire w)
                ^Acc plain-acc (:plain w)
                ^bytes scratch (:scratch w)
                want-len (alength plaintext)]
            ;; Clojure-specific. The message and one-shot entries return
            ;; a fresh array per call that the collector reclaims at the
            ;; end of the iteration; the pump accumulators are the
            ;; worker's own and are reused. The two postures meet in one
            ;; [got got-len] pair so a single comparison serves both.
            (let [outcome
                  (case shape
                    :stream
                    (let [pipe (:stream pipes)
                          t0 (System/nanoTime)
                          f (pump pipe true plaintext want-len wire-acc scratch)]
                      (if f
                        (cipher-fail r id iter shape "encrypt" (:what f) (:err f))
                        (do
                          (state/add-encrypt! c (- (System/nanoTime) t0))
                          (let [t1 (System/nanoTime)
                                g (pump pipe false (.accRaw wire-acc) (.accLen wire-acc)
                                        plain-acc scratch)]
                            (if g
                              (cipher-fail r id iter shape "decrypt" (:what g) (:err g))
                              (do
                                (state/add-decrypt! c (- (System/nanoTime) t1))
                                [(.accRaw plain-acc) (.accLen plain-acc)]))))))

                    :stream-one-shot
                    (let [pipe (:stream pipes)
                          t0 (System/nanoTime)
                          wire (try
                                 (itb/encrypt-stream-one-shot pipe plaintext)
                                 (catch Exception e
                                   (cipher-fail r id iter shape "encrypt" nil e)))]
                      (if (false? wire)
                        false
                        (do
                          (state/add-encrypt! c (- (System/nanoTime) t0))
                          (let [t1 (System/nanoTime)
                                got (try
                                      (itb/decrypt-stream-one-shot pipe wire)
                                      (catch Exception e
                                        (cipher-fail r id iter shape "decrypt" nil e)))]
                            (if (false? got)
                              false
                              (do
                                (state/add-decrypt! c (- (System/nanoTime) t1))
                                [got (alength ^bytes got)]))))))

                    (let [pipe (:msg pipes)
                          t0 (System/nanoTime)
                          wire (try
                                 (itb/encrypt-message pipe plaintext)
                                 (catch Exception e
                                   (cipher-fail r id iter shape "encrypt" nil e)))]
                      (if (false? wire)
                        false
                        (do
                          (state/add-encrypt! c (- (System/nanoTime) t0))
                          (let [t1 (System/nanoTime)
                                got (try
                                      (itb/decrypt-message pipe wire)
                                      (catch Exception e
                                        (cipher-fail r id iter shape "decrypt" nil e)))]
                            (if (false? got)
                              false
                              (do
                                (state/add-decrypt! c (- (System/nanoTime) t1))
                                [got (alength ^bytes got)])))))))]
              (if (false? outcome)
                false
                (let [[^bytes got got-len] outcome
                      got-len (long got-len)]
                  (when-not (Arrays/equals plaintext (int 0) (int want-len)
                                           got (int 0) (int got-len))
                    (report-mismatch id iter shape plaintext want-len got got-len))
                  (state/add-iteration! c want-len got-len)
                  true))))
          (finally
            (.unlock lock)))))))

(defn- worker-done
  "Marks this worker returned; the last one to return stamps the
  finish instant and wakes the launcher."
  [r]
  (let [^ReentrantLock lock (:done-lock r)]
    (.lock lock)
    (try
      (let [left (swap! (:active r) dec)]
        (when (zero? (long left))
          (reset! (:finish-nanos r) (System/nanoTime))
          (.signalAll ^java.util.concurrent.locks.Condition (:done-cond r))))
      (finally
        (.unlock lock)))))

(defn run-worker
  "The worker thread body: one warmup iteration, the warmup barrier,
  then the main loop until a stop is requested or the fixed per-worker
  iteration budget (warmup included) is spent. A failing warmup still
  passes both barriers so the launcher never waits on a worker that
  has already given up."
  [r w]
  ;; Warmup iteration — counted in the totals; its completion feeds
  ;; the post-warmup baselines.
  (let [ok (run-iteration r w 0)
        passed (try
                 (.await ^CyclicBarrier (:warmup-done r))
                 (.await ^CyclicBarrier (:release r))
                 true
                 (catch InterruptedException _
                   (.interrupt (Thread/currentThread))
                   false)
                 (catch BrokenBarrierException _ false))]
    (when (and passed ok)
      (let [cfg (:cfg r)
            iterations (long (:iterations cfg))]
        (loop [iter 1]
          (when-not (or (and (pos? iterations) (>= iter iterations))
                        (state/stop-requested? r))
            (when (and (run-iteration r w iter)
                       (ops/maintenance r (:id w) iter))
              (recur (inc iter)))))))
    (worker-done r)))
