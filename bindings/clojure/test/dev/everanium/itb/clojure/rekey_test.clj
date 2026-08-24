(ns dev.everanium.itb.clojure.rekey-test
  "Init → rekey! → open receiver with the rotated blob → round
  trip."
  (:require [clojure.test :refer [deftest is]]
            [dev.everanium.itb.clojure.core :as itb])
  (:import [java.util Arrays]))

(deftest rekey-round-trip
  (with-open [sender (itb/init "singlemsg-triple-mac-v1")]
    (let [blob-before (itb/blob sender)
          perm (byte-array 32)
          wrap (byte-array 32)]
      (Arrays/fill perm (unchecked-byte 0x11))
      (Arrays/fill wrap (unchecked-byte 0x22))
      (itb/rekey! sender perm wrap)
      (is (not (Arrays/equals ^bytes (itb/blob sender) ^bytes blob-before))
          "rekey must refresh the blob")
      (with-open [receiver (itb/open "singlemsg-triple-mac-v1" (itb/blob sender))]
        (let [plain (.getBytes "post-rekey payload" "UTF-8")
              wire (itb/encrypt-message sender plain)]
          (is (Arrays/equals ^bytes plain
                             ^bytes (itb/decrypt-message receiver wire))))))))
