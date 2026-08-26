;;;; itb-lfe — public API of the ITB LFE binding.
;;;;
;;;; Thin proxy over the ITB Erlang binding's `itb` module via native
;;;; BEAM bytecode interop — the LFE layer adds no FFI hop of its
;;;; own. No ITB construction logic lives in this binding: profile
;;;; names, opts keys, and every primitive name are opaque strings
;;;; passed through to Go for validation.
;;;;
;;;; The module is named `itb-lfe` (not `itb`) because the Erlang
;;;; binding's `itb` module shares the code path; a same-named module
;;;; would collide on load.
;;;;
;;;; Quick start:
;;;;
;;;;     (let* ((`#(ok ,sender) (itb-lfe:init #"singlemsg-triple-mac-v1"))
;;;;            (`#(ok ,blob) (itb-lfe:blob sender))
;;;;            (`#(ok ,receiver) (itb-lfe:open #"singlemsg-triple-mac-v1" blob))
;;;;            (`#(ok ,wire) (itb-lfe:encrypt-message sender #"hi"))
;;;;            (`#(ok ,plain) (itb-lfe:decrypt-message receiver wire)))
;;;;       (itb-lfe:free receiver)
;;;;       (itb-lfe:free sender)
;;;;       plain)
;;;;
;;;; Handles are opaque NIF resources owned by the Erlang layer:
;;;; dropping every term reference lets the garbage collector release
;;;; the Go-side state (libitb zeroes key material internally), and
;;;; `free/1` / `stream-free/1` release eagerly. A stream session
;;;; pins its parent pipeline, so the pipeline can never be collected
;;;; under a live session. Do not call `free/1` on a handle another
;;;; process is concurrently using — single-owner discipline per
;;;; handle, or drop references and let the collector free.
;;;;
;;;; Errors follow the `#(ok result) | #(error #(status detail))`
;;;; idiom: `status` is an atom mirroring the C binding's status
;;;; table (e.g. `mac_failure`, `bad_input`, `profile_exists`) and
;;;; `detail` the Go-side diagnostic binary.

(defmodule itb-lfe
  (export
    ;; Pipeline lifecycle
    (init 1) (init 2)
    (open 2) (open 3) (open 5)
    (blob 1)
    (rekey 3)
    (free 1)
    ;; Single Message encrypt / decrypt
    (encrypt-message 2)
    (decrypt-message 2)
    ;; One-shot stream encrypt / decrypt
    (encrypt-stream-one-shot 2)
    (decrypt-stream-one-shot 2)
    ;; Incremental stream sessions
    (encrypt-stream 1)
    (decrypt-stream 1)
    (stream-write 2)
    (stream-end 1)
    (stream-read 1) (stream-read 2)
    (stream-free 1)
    ;; Profile registration
    (register-profile 2)
    ;; Runtime + diagnostics
    (version 0)
    (hashes 0)
    (last-error 0)
    (set-memory-limit 1)
    (set-gc-percent 1)))

;;; ------------------------------------------------------------------
;;; Pipeline lifecycle
;;; ------------------------------------------------------------------

(defun init (profile)
  "As init/2 with pure profile defaults."
  (itb:init profile (map)))

(defun init (profile opts)
  "Constructs a fresh Pipeline against the named profile. Opts may be
  an empty map / property list for pure profile defaults; keys and
  values accumulate into the URL-query string consumed by libitb (the
  binding performs no validation — Go rejects unknown keys and bad
  values with a diagnostic in the error detail)."
  (itb:init profile opts))

(defun open (profile blob)
  "As open/3 with pure profile defaults."
  (itb:open profile blob (map)))

(defun open (profile blob opts)
  "Reconstructs a Pipeline from a blob produced by a sender's init /
  rekey, using the blob-embedded masters."
  (itb:open profile blob opts))

(defun open (profile blob opts perm-master wrap-master)
  "As open/3 with explicit master overrides. Both masters must be
  supplied non-empty (a half-supplied pair is rejected); pass
  #\"\" / #\"\" for the blob-embedded masters."
  (itb:open profile blob opts perm-master wrap-master))

(defun blob (pipeline)
  "The exported session-bundle blob for the receiver side; refreshed
  by rekey/3."
  (itb:blob pipeline))

(defun rekey (pipeline perm-master wrap-master)
  "Rotates the parallax + wrapper masters and refreshes the blob.
  Must not run concurrently with cipher calls or open stream sessions
  on the same Pipeline."
  (itb:rekey pipeline perm-master wrap-master))

(defun free (pipeline)
  "Eagerly closes (zeroing key material Go-side) and releases the
  handle. Idempotent; subsequent calls on the handle fail with
  #(error #(bad_handle _)). Garbage collection of the last term
  reference is the release backstop."
  (itb:free pipeline))

;;; ------------------------------------------------------------------
;;; Single Message encrypt / decrypt
;;; ------------------------------------------------------------------

(defun encrypt-message (pipeline plain)
  "One call, one self-contained wire."
  (itb:encrypt_message pipeline plain))

(defun decrypt-message (pipeline wire)
  "Receive-side counterpart of encrypt-message/2."
  (itb:decrypt_message pipeline wire))

;;; ------------------------------------------------------------------
;;; One-shot stream encrypt / decrypt
;;; ------------------------------------------------------------------

(defun encrypt-stream-one-shot (pipeline plain)
  "One-shot stream encrypt for callers holding the whole plaintext in
  memory: a single call through the Pipeline's stream chain. For
  bounded-memory streaming use the incremental encrypt-stream/1
  session."
  (itb:encrypt_stream_one_shot pipeline plain))

(defun decrypt-stream-one-shot (pipeline wire)
  "Receive-side counterpart of encrypt-stream-one-shot/2."
  (itb:decrypt_stream_one_shot pipeline wire))

;;; ------------------------------------------------------------------
;;; Incremental stream sessions
;;; ------------------------------------------------------------------

(defun encrypt-stream (pipeline)
  "Opens an incremental encrypt session (plaintext in, wire out). The
  session must not outlive its Pipeline (it pins the pipeline term,
  so dropping the pipeline reference alone never frees it early)."
  (itb:encrypt_stream pipeline))

(defun decrypt-stream (pipeline)
  "Receive-side counterpart (wire in, plaintext out)."
  (itb:decrypt_stream pipeline))

(defun stream-write (stream data)
  "Feeds data into the session. Blocks (on a dirty scheduler) until
  the cipher chain accepts the bytes; errors are sticky."
  (itb:stream_write stream data))

(defun stream-end (stream)
  "Signals end-of-input. Idempotent; a write after end fails with
  #(error #(bad_input _))."
  (itb:stream_end stream))

(defun stream-read (stream)
  "As stream-read/2 with a 1 MiB drain slice."
  (itb:stream_read stream))

(defun stream-read (stream max-bytes)
  "Drains up to max-bytes produced bytes. Returns
  #(ok data finished) — data may be #\"\" when nothing is currently
  available, and finished is 'true once the session has ended AND the
  output is fully drained. Partial drains are the normal mode. After
  stream-end/1, an empty-spool read blocks until the terminal bytes
  arrive or the session errors."
  (itb:stream_read stream max-bytes))

(defun stream-free (stream)
  "Cancels (if still running) and eagerly releases the session. Safe
  from any state — mid-flight, mid-error, or after a clean drain.
  Idempotent; garbage collection is the release backstop."
  (itb:stream_free stream))

;;; ------------------------------------------------------------------
;;; Profile registration
;;; ------------------------------------------------------------------

(defun register-profile (name opts)
  "Registers a user-defined Triple profile under name; the opts
  follow the register-profile grammar validated by Go. A duplicate
  name fails with #(error #(profile_exists _))."
  (itb:register_profile name opts))

;;; ------------------------------------------------------------------
;;; Runtime + diagnostics
;;; ------------------------------------------------------------------

(defun version ()
  "The libitb library version string (e.g. #\"0.3.0\")."
  (itb:version))

(defun hashes ()
  "The shipped hash primitive roster as a list of #(name width-bits)
  tuples in canonical registry order."
  (itb:hashes))

(defun last-error ()
  "The Go-side diagnostic recorded by the most recent failing libitb
  call (process-global last-write-wins; #\"\" when none). The error
  tuples already carry this detail — direct use is for ad-hoc
  debugging only."
  (itb:last_error))

(defun set-memory-limit (bytes)
  "Sets the Go runtime's soft heap limit in bytes; returns the
  previous limit. A negative value queries without changing."
  (itb:set_memory_limit bytes))

(defun set-gc-percent (pct)
  "Sets the Go GC trigger percentage; returns the previous value. A
  negative value queries without changing."
  (itb:set_gc_percent pct))
