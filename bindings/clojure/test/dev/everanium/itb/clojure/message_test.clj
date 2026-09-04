(ns dev.everanium.itb.clojure.message-test
  "Single Message round trip across every shipped cipher profile at
  small (4 KiB) and medium (256 KiB) payloads. The blob-only profile
  has no cipher surface and is exercised in errors-test instead."
  (:require [clojure.test :refer [deftest is]]
            [dev.everanium.itb.clojure.core :as itb])
  (:import [java.util Arrays]))

(defn payload
  "Deterministic non-trivial payload (xorshift fill)."
  ^bytes [n seed]
  (let [out (byte-array n)]
    (loop [i 0
           x (bit-or (long seed) 1)]
      (if (< i n)
        (let [x (bit-xor x (bit-shift-left x 13))
              x (bit-xor x (unsigned-bit-shift-right x 7))
              x (bit-xor x (bit-shift-left x 17))]
          (aset-byte out i (unchecked-byte x))
          (recur (inc i) x))
        out))))

(deftest message-round-trip-every-profile
  (doseq [profile ["streaming-aead-triple-mac-v1"
                   "streaming-noaead-triple-v1"
                   "singlemsg-triple-mac-v1"
                   "singlemsg-triple-nomac-v1"
                   "streaming-aead-triple-mac-mixed-v1"
                   "streaming-noaead-triple-mixed-v1"
                   "singlemsg-triple-mac-mixed-v1"
                   "singlemsg-triple-nomac-mixed-v1"]]
    (with-open [sender (itb/init profile)]
      (with-open [receiver (itb/load (itb/save sender))]
        (doseq [size [(* 4 1024) (* 256 1024)]]
          (let [plain (payload size size)
                wire (itb/encrypt-message sender plain)
                back (itb/decrypt-message receiver wire)]
            (is (Arrays/equals ^bytes plain ^bytes back)
                (str profile " @" size))))))))
