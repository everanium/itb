(ns io.github.everanium.itb3.clojure.runtime-test
  "Runtime diagnostics surface: GOMAXPROCS query / set / restore, the
  heap-profile writer, the pool-counter snapshot and its slot layout,
  and the hash-registry enumeration."
  (:require [clojure.test :refer [deftest is]]
            [io.github.everanium.itb3.clojure.core :as itb]
            [io.github.everanium.itb3.clojure.error :as err]
            [io.github.everanium.itb3.clojure.runtime :as runtime])
  (:import [java.io File]))

(deftest gomaxprocs-query-set-restore
  (let [orig (runtime/set-gomaxprocs! 0)]
    (is (pos? orig))
    ;; Zero and negative both query without changing.
    (is (= orig (runtime/set-gomaxprocs! -3)))
    (is (= orig (runtime/set-gomaxprocs! (inc orig))))
    (is (= (inc orig) (runtime/set-gomaxprocs! 0)))
    (is (= (inc orig) (runtime/set-gomaxprocs! orig)))))

(deftest heap-profile-written-empty-path-rejected
  (let [f (File/createTempFile "itb-clojure-heap-" ".prof")]
    (try
      (runtime/write-heap-profile! (.getAbsolutePath f))
      (is (pos? (.length f)))
      (finally
        (.delete f))))
  ;; The empty path falls back to ITB_MEMPROFILE inside libitb3; the
  ;; test environment sets no such variable, so there is nothing to
  ;; fall back to.
  (let [e (try
            (runtime/write-heap-profile! "")
            nil
            (catch clojure.lang.ExceptionInfo ex
              (when (err/itb-error? ex) ex)))]
    (is (= :bad-input (err/error-status e)))))

(deftest pool-counter-slot-layout
  (let [len (runtime/pool-stats-len)
        v (runtime/pool-stats)]
    (is (>= len 9))
    (is (= len (alength v)))
    (let [tiers (aget v 0)]
      (is (pos? tiers))
      (is (= (long len) (+ 1 (* 5 tiers) 8))))))

(deftest hash-registry-enumeration-is-canonical
  (let [names (itb/hash-names)]
    (is (= "aesitb128" (first names)))
    (is (some #{"areion512"} names))))
