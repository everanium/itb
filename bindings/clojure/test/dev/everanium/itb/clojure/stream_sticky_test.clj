(ns dev.everanium.itb.clojure.stream-sticky-test
  "A decrypt session fed a tampered wire fails with a sticky MAC
  failure. Uses a position probe rather than a single bit flip
  because the over-sized container carries CSPRNG residue in the
  non-payload area — a flip that lands inside the residue is
  architecturally inert (residue is not payload) and the session
  finishes clean. Probing 32 evenly-spaced positions makes the
  all-residue probability negligible; the first position that
  surfaces an error must give :mac-failure and remain sticky on
  subsequent reads."
  (:require [clojure.test :refer [deftest is]]
            [dev.everanium.itb.clojure.core :as itb]
            [dev.everanium.itb.clojure.error :as err]
            [dev.everanium.itb.clojure.stream :as stream])
  (:import [java.util Arrays]))

(def ^:private probes 32)

(defn- drain-until-error-or-finish
  "Drains the session; returns the first binding error, or nil when
  the session finished clean."
  [sess ^bytes buf]
  (try
    (loop []
      (stream/read! sess buf)
      (if (stream/finished? sess)
        nil
        (recur)))
    (catch clojure.lang.ExceptionInfo e
      (if (err/itb-error? e) e (throw e)))))

(defn- probe-once
  "Feeds one tampered wire through a fresh decrypt session. Returns
  :clean (residue hit) or runs the sticky assertions and returns
  :hit."
  [receiver ^bytes wire probe idx]
  (with-open [sess (itb/decrypt-stream receiver)]
    ;; Ignore write / end status — the failure may surface on either
    ;; side or only on the drain that follows.
    (try
      (stream/write! sess wire)
      (stream/end! sess)
      (catch clojure.lang.ExceptionInfo e
        (when-not (err/itb-error? e) (throw e))))
    (let [buf (byte-array 4096)
          first-err (drain-until-error-or-finish sess buf)]
      (if (nil? first-err)
        :clean
        (do
          (is (= :mac-failure (err/error-status first-err))
              (str "expected MAC failure on tampered wire at probe " probe
                   " (byte " idx "), got " (err/error-status first-err)))
          ;; Sticky: a subsequent read reports the same status.
          (let [again (try
                        (stream/read! sess buf)
                        nil
                        (catch clojure.lang.ExceptionInfo e e))]
            (is (some? again) "sticky failure must re-surface on read")
            (is (= (err/error-status first-err) (err/error-status again))))
          :hit)))))

(deftest tampered-wire-sticky-failure
  (with-open [sender (itb/init "streaming-aead-triple-mac-v1")]
    (with-open [receiver (itb/open "streaming-aead-triple-mac-v1" (itb/blob sender))]
      (let [plain (byte-array 65536)]
        (dotimes [i 65536]
          (aset-byte plain i (unchecked-byte (rem i 227))))
        (let [base-wire (itb/encrypt-stream-one-shot sender plain)]
          (is (> (alength ^bytes base-wire) 128)
              (str "wire too short to place a distributed probe: "
                   (alength ^bytes base-wire)))
          ;; Evenly spread through the wire body; skip the first /
          ;; last 16 bytes so a hit against the outer envelope
          ;; framing does not muddy the observation.
          (let [body-start 16
                body-end (- (alength ^bytes base-wire) 16)
                stride (quot (- body-end body-start) probes)
                outcome (loop [probe 0]
                          (if (< probe probes)
                            (let [idx (+ body-start (* probe stride))
                                  wire (Arrays/copyOf ^bytes base-wire
                                                      (alength ^bytes base-wire))]
                              (aset-byte wire idx
                                         (unchecked-byte (bit-xor (aget wire idx) 1)))
                              (if (= :hit (probe-once receiver wire probe idx))
                                :hit
                                (recur (inc probe))))
                            :exhausted))]
            (is (= :hit outcome)
                (str "no probe among " probes " evenly-spaced positions surfaced "
                     "a MAC failure — either the probe pattern is degenerate or "
                     "authentication is not covering the wire body it should"))))))))
