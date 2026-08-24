(ns dev.everanium.itb.clojure.core
  "Clojure lifetime wrapper around the Java binding's Pipeline.

  Zero FFI of its own — every call lands on the Java binding's
  in-process libitb proxy; this layer adds the Pipeline record with
  `with-open` compatibility, keyword opts maps, ex-info errors
  carrying status keywords, and the Session protocol over the
  incremental stream surface. Every hash-name / MAC-name /
  cipher-name / profile-name is an opaque string passed through to
  Go for validation; no ITB construction logic lives on the JVM
  side.

  A Pipeline record carries a Triple Pipeline session plus its
  exported blob bytes. The blob carries the session bundle the
  receiver feeds to `open`; `rekey!` refreshes it. Closing the
  Pipeline (or letting `with-open` do it) frees the handle — libitb
  zeroes key material internally; an unreachable un-closed Pipeline
  is reclaimed by the Java layer's Cleaner backstop.

  Streaming-decrypt caveat: chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication."
  (:require [dev.everanium.itb.clojure.error :refer [itb-call]]
            [dev.everanium.itb.clojure.opts :as opts]
            [dev.everanium.itb.clojure.stream :as stream])
  (:import [java.io InputStream OutputStream]))

(defrecord Pipeline [^com.everanium.itb.Pipeline impl]
  java.lang.AutoCloseable
  ;; Frees the Go-side handle (libitb closes it first, zeroing key
  ;; material). Idempotent; safe concurrently with GC.
  (close [_] (.close impl)))

(defn- jpipe
  "The wrapped Java Pipeline, hinted for static interop."
  ^com.everanium.itb.Pipeline [pipe]
  (:impl pipe))

(defn ^java.lang.AutoCloseable init
  "Constructs a fresh Pipeline against the named profile. Profile
  names and opts keys are opaque strings validated by the Go side;
  `opts-map` follows the dev.everanium.itb.clojure.opts roster.
  (The return tag lets `with-open` resolve `.close` statically; the
  value is a Pipeline record.)"
  ([profile] (init profile nil))
  ([profile opts-map]
   (->Pipeline
    (itb-call (com.everanium.itb.Pipeline/init ^String profile (opts/build opts-map))))))

(defn ^java.lang.AutoCloseable open
  "Reconstructs a Pipeline from a blob produced by `init` or
  `rekey!`. Omitting `perm-master` / `wrap-master` (or passing nil
  for both) uses the blob-embedded masters; supplying both
  (non-empty) overrides them."
  ([profile blob] (open profile blob nil))
  ([profile blob opts-map] (open profile blob opts-map nil nil))
  ([profile blob opts-map perm-master wrap-master]
   (->Pipeline
    (itb-call (com.everanium.itb.Pipeline/open ^String profile ^bytes blob
                                               (opts/build opts-map)
                                               ^bytes perm-master ^bytes wrap-master)))))

(defn register-profile!
  "Registers a user-defined Triple profile under `profile-name` so
  subsequent `init` / `open` calls resolve it. The opts follow the
  register-profile grammar validated by Go — build them with the
  :raw opts key plus the typed keywords where key names coincide. A
  duplicate name fails with :profile-exists."
  [profile-name opts-map]
  (itb-call (com.everanium.itb.Pipeline/registerProfile
             ^String profile-name (opts/build opts-map))))

(defn blob
  "The exported session bundle bytes for the receiver side."
  ^bytes [pipe]
  (itb-call (.blob (jpipe pipe))))

(defn rekey!
  "Rotates the parallax + wrapper masters and refreshes the blob.
  Must not run concurrently with cipher calls or open stream
  sessions on the same Pipeline."
  [pipe ^bytes perm-master ^bytes wrap-master]
  (itb-call (.rekey (jpipe pipe) perm-master wrap-master)))

(defn destroy!
  "Zeroes the Pipeline's key material and marks it closed while
  keeping the handle registered. Idempotent; subsequent cipher calls
  fail with :triple-closed. The handle itself is released by
  closing the Pipeline."
  [pipe]
  (itb-call (.destroy (jpipe pipe))))

(defn destroyed?
  "True once `destroy!` has run."
  [pipe]
  (.isDestroyed (jpipe pipe)))

(defn encrypt-message
  "Single Message encrypt: one call, one self-contained wire."
  ^bytes [pipe ^bytes plaintext]
  (itb-call (.encryptMessage (jpipe pipe) plaintext)))

(defn decrypt-message
  "Receive-side counterpart of `encrypt-message`."
  ^bytes [pipe ^bytes wire]
  (itb-call (.decryptMessage (jpipe pipe) wire)))

(defn encrypt-stream-one-shot
  "One-shot stream encrypt for callers holding the whole plaintext
  in memory. For bounded-memory streaming use `encrypt-stream` /
  `encrypt-stream-pump`."
  ^bytes [pipe ^bytes plaintext]
  (itb-call (.encryptStreamOneShot (jpipe pipe) plaintext)))

(defn decrypt-stream-one-shot
  "Receive-side counterpart of `encrypt-stream-one-shot`."
  ^bytes [pipe ^bytes wire]
  (itb-call (.decryptStreamOneShot (jpipe pipe) wire)))

(defn ^java.lang.AutoCloseable encrypt-stream
  "Opens an incremental encrypt session (plaintext in, wire out).
  The session implements the stream Session protocol and
  AutoCloseable, and pins `pipe` for its lifetime."
  [pipe]
  (stream/->EncryptSession pipe (itb-call (.encryptStream (jpipe pipe)))))

(defn ^java.lang.AutoCloseable decrypt-stream
  "Opens an incremental decrypt session (wire in, plaintext out).
  The session implements the stream Session protocol and
  AutoCloseable, and pins `pipe` for its lifetime."
  [pipe]
  (stream/->DecryptSession pipe (itb-call (.decryptStream (jpipe pipe)))))

(defn encrypt-stream-pump
  "Pumps the java.io.InputStream `src` through an encrypt session
  into the java.io.OutputStream `dst` with bounded memory: feed a
  slice, drain available wire, repeat; end + final drain on source
  EOF. The session is freed on return."
  [pipe ^InputStream src ^OutputStream dst]
  (itb-call (.encryptStreamPump (jpipe pipe) src dst)))

(defn decrypt-stream-pump
  "Receive-side counterpart of `encrypt-stream-pump`."
  [pipe ^InputStream src ^OutputStream dst]
  (itb-call (.decryptStreamPump (jpipe pipe) src dst)))
