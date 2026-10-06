(ns io.github.everanium.itb3.clojure.inner-hashes-test
  "Per-call constellation override via the typed :inner-hashes
  opts key: init a shipped width-512 base profile with an 8-entry
  width-512 alternate constellation, load the saved blob into a
  receiver, and round-trip a Single Message.

  The Clojure dispatcher branch for :inner-hashes delegates to the
  Java-side io.github.everanium.itb3.Opts#withInnerHashes(String[]) method."
  (:require [clojure.test :refer [deftest is]]
            [io.github.everanium.itb3.clojure.core :as itb])
  (:import [java.util Arrays]))

(deftest inner-hashes-override-round-trip
  ;; Base profile is a shipped single-primitive width-512 Single
  ;; Message profile; the per-call :inner-hashes override rebinds
  ;; all 8 slots to an alternate width-512 constellation for one
  ;; Pipeline pair without touching the shipped registry.
  (let [profile "singlemsg-triple-mac-v1"
        over    {:inner-hashes ["areion512" "blake2b512" "areion512" "blake2b512"
                                "areion512" "blake2b512" "areion512" "blake2b512"]}
        plain   (.getBytes "mixed-hashes typed override round trip" "UTF-8")]
    (with-open [sender (itb/init profile over)]
      (with-open [receiver (itb/load (itb/save sender))]
        (let [wire (itb/encrypt-message sender plain)]
          (is (Arrays/equals ^bytes plain
                             ^bytes (itb/decrypt-message receiver wire))))))))
