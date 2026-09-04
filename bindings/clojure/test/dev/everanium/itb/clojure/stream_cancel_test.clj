(ns dev.everanium.itb.clojure.stream-cancel-test
  "Closing an encrypt session mid-flight cleans up and leaves the
  Pipeline usable."
  (:require [clojure.test :refer [deftest is]]
            [dev.everanium.itb.clojure.core :as itb]
            [dev.everanium.itb.clojure.stream :as stream])
  (:import [java.util Arrays]))

(deftest close-mid-flight-then-reuse-pipeline
  (with-open [sender (itb/init "streaming-aead-triple-mac-v1")]
    (let [chunk (byte-array 100000)]
      (Arrays/fill chunk (unchecked-byte 0xA5))
      (with-open [sess (itb/encrypt-stream sender)]
        (stream/write! sess chunk)
        ;; Closed here without end! — close cancels and frees the
        ;; session; the test passing (process not hanging) is the
        ;; assertion.
        ))
    ;; The Pipeline stays usable after the cancelled session.
    (let [plain (.getBytes "after cancel" "UTF-8")]
      (with-open [receiver (itb/load (itb/save sender))]
        (let [wire (itb/encrypt-message sender plain)]
          (is (Arrays/equals ^bytes plain
                             ^bytes (itb/decrypt-message receiver wire))))))))
