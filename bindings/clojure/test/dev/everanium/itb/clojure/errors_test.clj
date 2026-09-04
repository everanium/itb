(ns dev.everanium.itb.clojure.errors-test
  "Error-mapping surface: opaque-string relay, destroyed Pipeline,
  duplicate profile registration (with an 8-entry mixed
  constellation), unknown lookup, max-workers! on a destroyed
  handle, and the ex-info error shape."
  (:require [clojure.test :refer [deftest is]]
            [dev.everanium.itb.clojure.core :as itb]
            [dev.everanium.itb.clojure.error :as err])
  (:import [java.util Arrays]))

(defmacro ^:private thrown-error
  "Runs body, returning the binding's ex-info error it throws (nil
  when nothing was thrown)."
  [& body]
  `(try
     ~@body
     nil
     (catch clojure.lang.ExceptionInfo e#
       (when (err/itb-error? e#) e#))))

(deftest unknown-profile-is-unknown-profile-with-diagnostic
  (let [e (thrown-error (itb/init "no-such-profile"))]
    (is (some? e))
    (is (= :unknown-profile (err/error-status e)))
    (is (seq (ex-message e)))))

(deftest unknown-opts-key-is-bad-input
  ;; Typoed key (lowercase s) — Go rejects unknown keys; the :raw
  ;; escape hatch relays it verbatim.
  (let [e (thrown-error
           (itb/init "singlemsg-triple-mac-v1" {:raw {"chunksize" "4096"}}))]
    (is (= :bad-input (err/error-status e)))))

(deftest unknown-opts-keyword-rejected-locally
  ;; A keyword outside the opts roster fails before any FFI call.
  (let [e (thrown-error (itb/init "singlemsg-triple-mac-v1" {:chunksize 4096}))]
    (is (= :bad-input (err/error-status e)))))

(deftest destroyed-pipeline-reports-triple-closed
  (with-open [p (itb/init "singlemsg-triple-mac-v1")]
    (itb/destroy! p)
    (is (itb/destroyed? p))
    (itb/destroy! p) ; idempotent
    (let [e (thrown-error (itb/encrypt-message p (.getBytes "payload" "UTF-8")))]
      (is (= :triple-closed (err/error-status e)))
      (is (= 25 (:code (ex-data e)))))))

(deftest register-mixed-then-duplicate
  ;; 8-entry width-256 mixed constellation, layers off.
  (let [record {:mode "singlemsg-nomac"
                :width 256
                :hashes ["blake3" "blake2s" "areion256" "blake2b256"
                         "chacha20" "blake3" "blake2s" "areion256"]
                :key-bits 1024
                :parallax? false
                :wrapper? false}]
    (itb/register! "clojure-binding-test-mixed" record)
    ;; The registered profile round-trips.
    (let [plain (.getBytes "custom profile" "UTF-8")]
      (with-open [sender (itb/init "clojure-binding-test-mixed")]
        (with-open [receiver (itb/load (itb/save sender))]
          (let [wire (itb/encrypt-message sender plain)]
            (is (Arrays/equals ^bytes plain
                               ^bytes (itb/decrypt-message receiver wire)))))))
    ;; Duplicate name is a distinct status.
    (let [e (thrown-error (itb/register! "clojure-binding-test-mixed" record))]
      (is (= :profile-exists (err/error-status e))))))

(deftest lookup-unknown-name-is-unknown-profile
  (let [e (thrown-error (itb/lookup "no-such-profile"))]
    (is (= :unknown-profile (err/error-status e)))
    (is (= 13 (:code (ex-data e))))))

(deftest max-workers-on-destroyed-pipeline-is-triple-closed
  (with-open [p (itb/init "singlemsg-triple-mac-v1")]
    (itb/destroy! p)
    (let [e (thrown-error (itb/max-workers! p 2))]
      (is (= :triple-closed (err/error-status e))))))

(deftest opaque-primitive-name-relay
  ;; An unknown inner-hash name is relayed to Go and rejected there —
  ;; the binding performs no name validation of its own.
  (let [e (thrown-error
           (itb/init "singlemsg-triple-mac-v1" {:inner-hash "no-such-hash"}))]
    (is (some? e))
    (is (not= :ok (err/error-status e)))))
