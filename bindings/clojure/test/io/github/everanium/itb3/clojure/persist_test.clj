(ns io.github.everanium.itb3.clojure.persist-test
  "Session persistence surface: save / load, save-f / load-f,
  inspect, lookup / profiles / register! round trip, max-workers!
  clamping."
  (:require [clojure.test :refer [deftest is]]
            [io.github.everanium.itb3.clojure.core :as itb])
  (:import [java.nio.file Files]
           [java.util Arrays]))

(def ^:private plain (.getBytes "persisted session payload" "UTF-8"))

(defn- round-trips? [sender receiver]
  (Arrays/equals ^bytes plain
                 ^bytes (itb/decrypt-message receiver (itb/encrypt-message sender plain))))

(deftest save-then-load-round-trip
  (with-open [sender (itb/init "singlemsg-triple-mac-v1")]
    (let [blob (itb/save sender)]
      (is (pos? (alength ^bytes blob)))
      (is (Arrays/equals ^bytes blob ^bytes (itb/save sender)))
      (with-open [receiver (itb/load blob)]
        (is (Arrays/equals ^bytes blob ^bytes (itb/save receiver)))
        (is (round-trips? sender receiver))))))

(deftest save-f-then-load-f-round-trip
  (let [dir (Files/createTempDirectory "itb-clojure-" (make-array java.nio.file.attribute.FileAttribute 0))
        file (.resolve dir "session.blob")]
    (try
      (with-open [sender (itb/init "streaming-aead-triple-mac-v1")]
        (itb/save-f sender (str file))
        (is (Arrays/equals ^bytes (Files/readAllBytes file) ^bytes (itb/save sender)))
        (with-open [receiver (itb/load-f (str file))]
          (is (Arrays/equals ^bytes plain
                             ^bytes (itb/decrypt-stream-one-shot
                                     receiver (itb/encrypt-stream-one-shot sender plain))))))
      (finally
        (Files/deleteIfExists file)
        (Files/deleteIfExists dir)))))

(deftest load-with-master-override
  (let [perm (byte-array 32 (byte 0x33))
        wrap (byte-array 32 (byte 0x44))]
    (with-open [sender (itb/init "singlemsg-triple-mac-v1")]
      (let [blob (itb/save sender)
            rotated (itb/rekey! sender perm wrap)]
        (is (not (Arrays/equals ^bytes blob ^bytes rotated)))
        (is (Arrays/equals ^bytes rotated ^bytes (itb/save sender)))
        (with-open [receiver (itb/load blob perm wrap)]
          (is (round-trips? sender receiver)))))))

(deftest inspect-reads-the-embedded-record
  (with-open [pipe (itb/init "streaming-aead-triple-mac-v1")]
    (let [prof (itb/inspect (itb/save pipe))]
      (is (= "streaming-aead-triple-mac-v1" (:name prof)))
      (is (= "streaming-aead" (:mode prof)))
      (is (= 512 (:width prof)))
      ;; The recipe keys match the registry entry; the two
      ;; inspection-only keys separate the two records.
      (is (= (itb/lookup "streaming-aead-triple-mac-v1")
             (assoc prof :nonce-bits nil :barrier-fill nil))))))

(deftest inspect-carries-the-runtime-globals-lookup-does-not
  ;; Defaults: the blob records the compile-in nonce width and
  ;; barrier fill margin, and inspect surfaces both.
  (with-open [pipe (itb/init "streaming-aead-triple-mac-v1")]
    (let [prof (itb/inspect (itb/save pipe))]
      (is (= 512 (:nonce-bits prof)))
      (is (= 1 (:barrier-fill prof)))))
  ;; Per-Pipeline overrides travel through the blob into inspect.
  (with-open [pipe (itb/init "streaming-aead-triple-mac-v1"
                             {:nonce-bits 256 :barrier-fill 4})]
    (let [prof (itb/inspect (itb/save pipe))]
      (is (= 256 (:nonce-bits prof)))
      (is (= 4 (:barrier-fill prof)))))
  ;; The registry entry is the recipe alone — neither key is part of
  ;; it, so both read as absent rather than as zero.
  (let [registry (itb/lookup "streaming-aead-triple-mac-v1")]
    (is (nil? (:nonce-bits registry)))
    (is (nil? (:barrier-fill registry)))))

(deftest profiles-lists-the-catalogue
  (let [names (set (itb/profiles))]
    (is (contains? names "singlemsg-triple-mac-v1"))
    (is (contains? names "streaming-aead-triple-mac-v1"))))

(deftest register-copy-of-shipped-profile
  (let [copy (assoc (itb/lookup "singlemsg-triple-nomac-v1") :name "")]
    (itb/register! "clojure-binding-test-copy" copy)
    (let [back (itb/lookup "clojure-binding-test-copy")]
      (is (= "clojure-binding-test-copy" (:name back)))
      (is (= (:mode copy) (:mode back))))
    (is (some #{"clojure-binding-test-copy"} (itb/profiles)))
    (with-open [sender (itb/init "clojure-binding-test-copy")]
      (with-open [receiver (itb/load (itb/save sender))]
        (is (round-trips? sender receiver))))))

(deftest max-workers-clamps
  (with-open [pipe (itb/init "singlemsg-triple-mac-v1" {:max-workers -1})]
    (itb/max-workers! pipe 2)
    (itb/max-workers! pipe -1)
    (itb/max-workers! pipe 1000)
    (is (round-trips? pipe pipe))))
