(ns dev.everanium.itb.clojure.bench-stream-one-shot
  "Whole-buffer Stream throughput vs plaintext size (Streaming
  Non-AEAD profile) at 1 MiB / 16 MiB / 64 MiB. Times
  encrypt-stream-one-shot / decrypt-stream-one-shot, the single FFI
  round-trip surface for callers holding the whole payload in
  memory."
  (:require [dev.everanium.itb.clojure.bench-util :as u]
            [dev.everanium.itb.clojure.core :as itb]))

(defn run []
  (with-open [pipe (itb/init (u/profile-name "streaming-noaead-triple-v1")
                             (u/build-opts))]
    (u/header)
    (doseq [size u/sizes]
      (let [plain (byte-array size)]
        (u/csprng-fill plain)
        (u/bench-case "stream_one_shot" size
                      #(itb/encrypt-stream-one-shot pipe plain))
        ;; Pre-encrypt one wire outside the decrypt timing loop.
        (let [dec-wire (itb/encrypt-stream-one-shot pipe plain)]
          (u/bench-case "stream_one_shot-dec" size
                        #(itb/decrypt-stream-one-shot pipe dec-wire)))))))

(defn -main [& _]
  (u/apply-runtime-caps!)
  (run)
  (System/exit 0))
