(ns dev.everanium.itb.clojure.smoke-test
  "Init → save → load → encrypt-message → decrypt-message round
  trip."
  (:require [clojure.test :refer [deftest is]]
            [dev.everanium.itb.clojure.core :as itb])
  (:import [java.util Arrays]))

(deftest smoke-round-trip
  (let [plain (.getBytes "smoke round-trip payload" "UTF-8")]
    (with-open [sender (itb/init "singlemsg-triple-mac-v1")]
      (is (pos? (alength (itb/save sender))))
      (with-open [receiver (itb/load (itb/save sender))]
        (let [wire (itb/encrypt-message sender plain)]
          (is (not (Arrays/equals ^bytes wire ^bytes plain)))
          (is (Arrays/equals ^bytes plain ^bytes (itb/decrypt-message receiver wire))))))))
