(ns dev.everanium.itb.clojure.bench-stream
  "Stream-pump throughput vs plaintext size (Streaming Non-AEAD
  profile) at 1 MiB / 16 MiB / 64 MiB."
  (:require [dev.everanium.itb.clojure.bench-util :as u]
            [dev.everanium.itb.clojure.core :as itb])
  (:import [java.io ByteArrayInputStream ByteArrayOutputStream]))

(defn run []
  (with-open [pipe (itb/init (u/profile-name "streaming-noaead-triple-v1")
                             (u/build-opts))]
    (u/header)
    (doseq [size u/sizes]
      (let [plain (byte-array size)]
        (u/csprng-fill plain)
        (u/bench-case "stream_pump" size
                      (fn []
                        (let [wire (ByteArrayOutputStream.
                                    (+ (long size) (quot (long size) 4) 131072))]
                          (itb/encrypt-stream-pump
                           pipe (ByteArrayInputStream. plain) wire))))
        ;; Pre-encrypt one wire outside the decrypt timing loop.
        (let [setup-wire (ByteArrayOutputStream.
                          (+ (long size) (quot (long size) 4) 131072))]
          (itb/encrypt-stream-pump pipe (ByteArrayInputStream. plain) setup-wire)
          (let [dec-wire (.toByteArray setup-wire)]
            (u/bench-case "stream_pump-dec" size
                          (fn []
                            (let [out (ByteArrayOutputStream.
                                       (+ (long size) 131072))]
                              (itb/decrypt-stream-pump
                               pipe (ByteArrayInputStream. dec-wire) out))))))))))

(defn -main [& _]
  (u/apply-runtime-caps!)
  (run)
  (System/exit 0))
