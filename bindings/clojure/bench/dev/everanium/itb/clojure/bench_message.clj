(ns dev.everanium.itb.clojure.bench-message
  "encrypt-message throughput vs plaintext size (Single Message
  profile) at 1 MiB / 16 MiB / 64 MiB."
  (:require [dev.everanium.itb.clojure.bench-util :as u]
            [dev.everanium.itb.clojure.core :as itb]))

(defn run []
  (with-open [pipe (itb/init (u/profile-name "singlemsg-triple-nomac-v1")
                             (u/build-opts))]
    (u/header)
    (doseq [size u/sizes]
      (let [plain (byte-array size)]
        (u/csprng-fill plain)
        (u/bench-case "message" size #(itb/encrypt-message pipe plain))
        ;; Pre-encrypt one wire outside the decrypt timing loop.
        (let [dec-wire (itb/encrypt-message pipe plain)]
          (u/bench-case "message-dec" size
                        #(itb/decrypt-message pipe dec-wire)))))))

(defn -main [& _]
  (u/apply-runtime-caps!)
  (run)
  (System/exit 0))
