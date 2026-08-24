(ns dev.everanium.itb.clojure.stream-pump-test
  "Round trip through the stream pumps on a Streaming AEAD profile."
  (:require [clojure.test :refer [deftest is]]
            [dev.everanium.itb.clojure.core :as itb])
  (:import [java.io ByteArrayInputStream ByteArrayOutputStream]
           [java.util Arrays]))

(defn- mod-fill ^bytes [n m]
  (let [out (byte-array n)]
    (loop [i 0]
      (when (< i n)
        (aset-byte out i (unchecked-byte (rem i m)))
        (recur (inc i))))
    out))

(deftest pump-round-trip-1mib
  (with-open [sender (itb/init "streaming-aead-triple-mac-v1")]
    (with-open [receiver (itb/open "streaming-aead-triple-mac-v1" (itb/blob sender))]
      (let [plain (mod-fill (bit-shift-left 1 20) 251)
            wire (ByteArrayOutputStream.)]
        (itb/encrypt-stream-pump sender (ByteArrayInputStream. plain) wire)
        (is (pos? (.size wire)))
        (let [back (ByteArrayOutputStream.)]
          (itb/decrypt-stream-pump receiver (ByteArrayInputStream. (.toByteArray wire)) back)
          (is (Arrays/equals ^bytes plain ^bytes (.toByteArray back))))))))

(deftest pump-matches-one-shot
  (with-open [sender (itb/init "streaming-aead-triple-mac-v1")]
    (with-open [receiver (itb/open "streaming-aead-triple-mac-v1" (itb/blob sender))]
      (let [plain (mod-fill 65536 199)
            wire (itb/encrypt-stream-one-shot sender plain)
            back (ByteArrayOutputStream.)]
        (itb/decrypt-stream-pump receiver (ByteArrayInputStream. wire) back)
        (is (Arrays/equals ^bytes plain ^bytes (.toByteArray back)))
        (is (Arrays/equals ^bytes plain
                           ^bytes (itb/decrypt-stream-one-shot receiver wire)))))))
