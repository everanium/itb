(ns io.github.everanium.itb3.clojure.loop.ops
  "The maintenance operations that mutate a live Pipeline handle
  between iterations: master rotation (--rekey-every) and blob reopen
  (--blob-cycle-every)."
  (:require [io.github.everanium.itb3.clojure.core :as itb]
            [io.github.everanium.itb3.clojure.loop.payload :as payload]
            [io.github.everanium.itb3.clojure.loop.state :as state])
  (:import [java.util.concurrent.atomic AtomicLong]
           [java.util.concurrent.locks ReentrantReadWriteLock]))

(def ^:private rekey-master-size
  "Byte length of each fresh master drawn for a rotation. Matches the
  size Init auto-generates for both the parallax and the wrapper
  master."
  32)

(def ^:private no-master
  "The empty master a disabled layer passes; Rekey ignores it."
  (byte-array 0))

(defn- write-lock ^java.util.concurrent.locks.Lock [r]
  (.writeLock ^ReentrantReadWriteLock (:pipes-lock r)))

(defn- rekey-pipes
  "Master rotation. Rotates the parallax + wrapper masters on every
  active Pipeline under the write lock and retains the refreshed blob
  for subsequent blob reopens. Masters are drawn fresh from the OS
  CSPRNG on every rotation regardless of --seed (master rotation is
  pipeline keying, not plaintext content); a disabled layer passes no
  bytes, which Rekey ignores. The eight inner seeds and the MAC key
  are untouched by design — Rekey targets only the two outer-layer
  master secrets."
  [r ^long id ^long iter]
  (let [cfg (:cfg r)
        perm (if (:parallax cfg) (byte-array rekey-master-size) no-master)
        wrap (if (:wrapper cfg) (byte-array rekey-master-size) no-master)]
    (if-not (and (or (not (:parallax cfg)) (payload/fill-random perm))
                 (or (not (:wrapper cfg)) (payload/fill-random wrap)))
      (state/fail r id (str "g" id " iter " iter ": csprng: rekey master"))
      (let [lock (write-lock r)
            _ (.lock lock)
            outcome (try
                      (let [p @(:pipes r)]
                        (or (when-let [pipe (:stream p)]
                              (try
                                (swap! (:pipes r) assoc :stream-blob
                                       (itb/rekey! pipe perm wrap))
                                nil
                                (catch Exception e
                                  (str "g" id " iter " iter ": Rekey("
                                       (:stream-profile r) "): " (state/detail e)))))
                            (when-let [pipe (:msg p)]
                              (try
                                (swap! (:pipes r) assoc :msg-blob
                                       (itb/rekey! pipe perm wrap))
                                nil
                                (catch Exception e
                                  (str "g" id " iter " iter ": Rekey("
                                       (:msg-profile r) "): " (state/detail e)))))))
                      (finally (.unlock lock)))]
        (if outcome
          (state/fail r id outcome)
          (let [n (.incrementAndGet ^AtomicLong (:rekeys r))]
            (state/log-line (str "rekey: g" id " iter " iter
                                 " rotated parallax + wrapper masters (rekey #" n ")"))
            true))))))

(defn- blob-cycle-pipes
  "Blob reopen. Reopens every active Pipeline from its retained blob
  under the write lock: a fresh handle is loaded from the blob, the
  running handle is freed, and the fresh one is swapped in, so every
  later iteration round-trips through seeds and masters that survived
  a blob crossing. The input is the blob Init or the latest Rekey
  handed out, not a fresh Save: that is what a receiver holds, and
  reopening from it proves the handed-out bytes rather than the live
  state. The blob carries the Pipeline's full shape, so no override
  reaches the reopen. On a Load failure the running handle stays and
  the failure aborts the run."
  [r ^long id ^long iter]
  (let [lock (write-lock r)
        _ (.lock lock)
        outcome (try
                  (let [p @(:pipes r)]
                    (or (when-let [running (:stream p)]
                          (try
                            (let [fresh (itb/load (:stream-blob p))]
                              (.close ^java.lang.AutoCloseable running)
                              (swap! (:pipes r) assoc :stream fresh)
                              nil)
                            (catch Exception e
                              (str "g" id " iter " iter ": Load("
                                   (:stream-profile r) "): " (state/detail e)))))
                        (when-let [running (:msg p)]
                          (try
                            (let [fresh (itb/load (:msg-blob p))]
                              (.close ^java.lang.AutoCloseable running)
                              (swap! (:pipes r) assoc :msg fresh)
                              nil)
                            (catch Exception e
                              (str "g" id " iter " iter ": Load("
                                   (:msg-profile r) "): " (state/detail e)))))))
                  (finally (.unlock lock)))]
    (if outcome
      (state/fail r id outcome)
      (let [n (.incrementAndGet ^AtomicLong (:blob-cycles r))]
        (state/log-line (str "blob-cycle: g" id " iter " iter
                             " reopened from session blob (cycle #" n ")"))
        true))))

(defn maintenance
  "Handle mutation. Runs the periodic Pipeline-mutating operations
  after a completed iteration: master rotation (--rekey-every) and
  blob reopen (--blob-cycle-every). Both intervals count per-worker
  iterations; the warmup iteration (iter 0) never triggers because the
  worker loop calls this for iter >= 1 only. Rekey rewrites the
  outer-layer keying of a live handle and a blob reopen replaces the
  handle outright; each takes the write lock, so in-flight cipher
  calls on other workers drain before anything changes and no encrypt
  is separated from its decrypt by either. False after recording the
  worker error."
  [r ^long id ^long iter]
  (let [cfg (:cfg r)
        rekey-every (long (:rekey-every cfg))
        blob-every (long (:blob-cycle-every cfg))]
    (if (and (pos? rekey-every)
             (zero? (rem iter rekey-every))
             (not (rekey-pipes r id iter)))
      false
      (if (and (pos? blob-every)
               (zero? (rem iter blob-every))
               (not (blob-cycle-pipes r id iter)))
        false
        true))))
