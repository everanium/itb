(ns dev.everanium.itb.clojure.stream-incremental-test
  "Explicit write! / end! / read! round trip with pathological batch
  sizes (17-byte feed, 23-byte drain) across multiple chunks. The
  same side function drives both the encrypt and the decrypt
  session through the Session protocol."
  (:require [clojure.test :refer [deftest is]]
            [dev.everanium.itb.clojure.core :as itb]
            [dev.everanium.itb.clojure.stream :as stream])
  (:import [java.io ByteArrayOutputStream]
           [java.util Arrays]))

(defn- round-trip-side
  "Feeds `input` in 17-byte writes, ends, drains in 23-byte reads."
  ^bytes [sess ^bytes input]
  (let [n (alength input)]
    (loop [off 0]
      (when (< off n)
        (stream/write! sess input off (min 17 (- n off)))
        (recur (+ off 17)))))
  (stream/end! sess)
  (let [out (ByteArrayOutputStream.)
        buf (byte-array 23)]
    (loop []
      (when-not (stream/finished? sess)
        (let [{n :count} (stream/read! sess buf)]
          (.write out buf 0 (int n)))
        (recur)))
    (.toByteArray out)))

(deftest incremental-tiny-batches
  ;; Small chunk size so the 64 KiB payload spans many chunks.
  (let [opts {:chunk-size 4096}]
    (with-open [sender (itb/init "streaming-aead-triple-mac-v1" opts)]
      (with-open [receiver (itb/open "streaming-aead-triple-mac-v1"
                                     (itb/blob sender) opts)]
        (let [plain (byte-array 65536)]
          (dotimes [i 65536]
            (aset-byte plain i (unchecked-byte (rem i 241))))
          (let [wire (with-open [sess (itb/encrypt-stream sender)]
                       (round-trip-side sess plain))]
            (is (pos? (alength ^bytes wire)))
            (let [back (with-open [sess (itb/decrypt-stream receiver)]
                         (round-trip-side sess wire))]
              (is (Arrays/equals ^bytes plain ^bytes back)))))))))
