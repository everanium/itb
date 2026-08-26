;;;; itb-lfe-tests — EUnit suite for the LFE binding, written with
;;;; the ltest macros. Covers: version, the hash primitive roster
;;;; (canonical registry order), the Single Message round trip, the
;;;; incremental stream pump round trip, runtime knobs, profile
;;;; registration, and the error-mapping surface (unknown profile,
;;;; tampered wire, freed handles).
;;;;
;;;; The pump / pair helpers mirror the Erlang binding's
;;;; itb_test_util module (bindings/erlang/test/itb_test_util.erl).

(defmodule itb-lfe-tests
  (behaviour ltest-unit))

(include-lib "ltest/include/ltest-macros.lfe")

;; 1 MiB feed / drain slice for the pump helpers.
(defmacro SLICE () `,(bsl 1 20))

;;; ------------------------------------------------------------------
;;; Version / roster / runtime knobs
;;; ------------------------------------------------------------------

(deftest version
  (let ((`#(ok ,version) (itb-lfe:version)))
    (is (> (byte_size version) 0))))

(deftest hashes-canonical-order
  ;; Canonical registry order fixture; names and widths mirror the
  ;; C ABI iteration surface (ITB_HashName / ITB_HashWidth).
  (is-equal
    (list #(#"areion256" 256)
          #(#"areion512" 512)
          #(#"blake2b256" 256)
          #(#"blake2b512" 512)
          #(#"blake2s" 256)
          #(#"blake3" 256)
          #(#"aescmac" 128)
          #(#"siphash24" 128)
          #(#"chacha20" 256))
    (itb-lfe:hashes)))

(deftest runtime-knobs-query-without-changing
  ;; Negative values query without changing; the return is the
  ;; previous setting.
  (let ((prev (itb-lfe:set-memory-limit -1)))
    (is (is_integer prev))
    (is-equal prev (itb-lfe:set-memory-limit -1)))
  (is (is_integer (itb-lfe:set-gc-percent -2))))

;;; ------------------------------------------------------------------
;;; Single Message round trip (MAC Authenticated profile)
;;; ------------------------------------------------------------------

(deftestgen smoke-round-trip
  (tuple 'timeout 120
    (lambda ()
      (let* ((`#(ok ,sender) (itb-lfe:init #"singlemsg-triple-mac-v1"))
             (`#(ok ,blob) (itb-lfe:blob sender)))
        (is (> (byte_size blob) 0))
        (let* ((`#(ok ,receiver)
                 (itb-lfe:open #"singlemsg-triple-mac-v1" blob))
               (plain #"smoke round-trip payload")
               (`#(ok ,wire) (itb-lfe:encrypt-message sender plain)))
          (is-not-equal plain wire)
          (let ((`#(ok ,back) (itb-lfe:decrypt-message receiver wire)))
            (is-equal plain back))
          (is-equal 'ok (itb-lfe:free receiver))
          (is-equal 'ok (itb-lfe:free sender)))))))

;;; ------------------------------------------------------------------
;;; Incremental stream pump round trip (Streaming Non-AEAD profile)
;;; ------------------------------------------------------------------

(deftestgen stream-pump-round-trip
  (tuple 'timeout 240
    (lambda ()
      (let ((`#(,sender ,receiver) (pair #"streaming-noaead-triple-v1"))
            (plain (crypto:strong_rand_bytes (+ (bsl 1 20) 12345))))
        (let ((wire (pump sender 'encrypt plain)))
          (is (> (byte_size wire) (byte_size plain)))
          (is-equal plain (pump receiver 'decrypt wire)))
        (is-equal 'ok (itb-lfe:free receiver))
        (is-equal 'ok (itb-lfe:free sender))))))

(deftestgen stream-zero-length-payload
  ;; The Non-AEAD stream wire is body-only: a zero-length payload
  ;; yields a zero-length wire, and the round trip still holds.
  (tuple 'timeout 120
    (lambda ()
      (let ((`#(,sender ,receiver) (pair #"streaming-noaead-triple-v1")))
        (let ((wire (pump sender 'encrypt #"")))
          (is-equal #"" (pump receiver 'decrypt wire)))
        (is-equal 'ok (itb-lfe:free receiver))
        (is-equal 'ok (itb-lfe:free sender))))))

;;; ------------------------------------------------------------------
;;; One-shot stream round trip (Streaming AEAD profile)
;;; ------------------------------------------------------------------

(deftestgen stream-one-shot-round-trip
  (tuple 'timeout 240
    (lambda ()
      (let ((`#(,sender ,receiver) (pair #"streaming-aead-triple-mac-v1"))
            (plain (crypto:strong_rand_bytes (+ (bsl 1 18) 12345))))
        ;; One-shot both ways, then cross-check against the
        ;; incremental session path in each direction.
        (let ((`#(ok ,wire) (itb-lfe:encrypt-stream-one-shot sender plain)))
          (is (> (byte_size wire) (byte_size plain)))
          (let ((`#(ok ,back) (itb-lfe:decrypt-stream-one-shot receiver wire)))
            (is-equal plain back))
          (is-equal plain (pump receiver 'decrypt wire)))
        (let* ((wire2 (pump sender 'encrypt plain))
               (`#(ok ,back2) (itb-lfe:decrypt-stream-one-shot receiver wire2)))
          (is-equal plain back2))
        (is-equal 'ok (itb-lfe:free receiver))
        (is-equal 'ok (itb-lfe:free sender))))))

;;; ------------------------------------------------------------------
;;; Profile registration
;;; ------------------------------------------------------------------

(deftestgen register-profile-round-trip
  (tuple 'timeout 240
    (lambda ()
      (let ((opts (map #"mode" #"singlemsg-nomac"
                       #"width" 256
                       #"innerHashes" (binary
                         "blake3,blake2s,areion256,blake2b256,"
                         "chacha20,blake3,blake2s,areion256")
                       #"keyBits" 1024
                       #"parallaxOn" 'false
                       #"wrapperOn" 'false)))
        (is-equal 'ok (itb-lfe:register-profile #"lfe-binding-test-mixed"
                                                opts))
        ;; A duplicate registration fails with profile_exists.
        (let ((`#(error #(profile_exists ,_))
                (itb-lfe:register-profile #"lfe-binding-test-mixed" opts)))
          'ok)
        (let ((`#(,sender ,receiver) (pair #"lfe-binding-test-mixed"))
              (plain (crypto:strong_rand_bytes 8192)))
          (let* ((`#(ok ,wire) (itb-lfe:encrypt-message sender plain))
                 (`#(ok ,back) (itb-lfe:decrypt-message receiver wire)))
            (is-equal plain back))
          (is-equal 'ok (itb-lfe:free receiver))
          (is-equal 'ok (itb-lfe:free sender)))))))

;;; ------------------------------------------------------------------
;;; Error mapping
;;; ------------------------------------------------------------------

(deftest unknown-profile
  (let ((`#(error #(bad_input ,detail))
          (itb-lfe:init #"no-such-profile")))
    (is (> (byte_size detail) 0))))

(deftest unknown-inner-hash
  ;; An unknown inner-hash name is relayed to Go and rejected there.
  (let ((`#(error ,_) (itb-lfe:init #"singlemsg-triple-mac-v1"
                                    (map #"innerHash" #"no-such-hash"))))
    'ok))

(deftest malformed-blob
  (let ((`#(error ,_) (itb-lfe:open #"singlemsg-triple-mac-v1"
                                    #"not a session blob")))
    'ok))

;; A bit flip in authenticated wire content fails with mac_failure.
;; A single flip can land in the container's CSPRNG residue — where
;; the decrypt legitimately completes clean — so successive flip
;; positions are probed until one lands in authenticated content.
(deftestgen tampered-message
  (tuple 'timeout 300
    (lambda ()
      (let ((`#(,sender ,receiver) (pair #"singlemsg-triple-mac-v1"))
            (plain (crypto:strong_rand_bytes 4096)))
        (let ((`#(ok ,wire) (itb-lfe:encrypt-message sender plain)))
          (is (probe-flip receiver wire 0)))
        (is-equal 'ok (itb-lfe:free receiver))
        (is-equal 'ok (itb-lfe:free sender))))))

(deftest freed-pipeline
  (let ((`#(ok ,pipe) (itb-lfe:init #"singlemsg-triple-mac-v1")))
    (is-equal 'ok (itb-lfe:free pipe))
    (is-equal 'ok (itb-lfe:free pipe)) ;; idempotent
    (let ((`#(error #(bad_handle ,_)) (itb-lfe:encrypt-message pipe #"x")))
      'ok)
    (let ((`#(error #(bad_handle ,_)) (itb-lfe:blob pipe)))
      'ok)
    (let ((`#(error #(bad_handle ,_)) (itb-lfe:encrypt-stream pipe)))
      'ok)))

(deftestgen freed-stream
  (tuple 'timeout 120
    (lambda ()
      (let* ((`#(ok ,pipe) (itb-lfe:init #"streaming-noaead-triple-v1"))
             (`#(ok ,stream) (itb-lfe:encrypt-stream pipe)))
        (is-equal 'ok (itb-lfe:stream-free stream))
        (is-equal 'ok (itb-lfe:stream-free stream)) ;; idempotent
        (let ((`#(error #(bad_handle ,_)) (itb-lfe:stream-write stream #"x")))
          'ok)
        (let ((`#(error #(bad_handle ,_)) (itb-lfe:stream-end stream)))
          'ok)
        (let ((`#(error #(bad_handle ,_)) (itb-lfe:stream-read stream 16)))
          'ok)
        (is-equal 'ok (itb-lfe:free pipe))))))

;;; ------------------------------------------------------------------
;;; Helpers (not tests)
;;; ------------------------------------------------------------------

;; Sender + receiver pipelines over one profile with default opts.
(defun pair (profile)
  (let* ((`#(ok ,sender) (itb-lfe:init profile))
         (`#(ok ,blob) (itb-lfe:blob sender))
         (`#(ok ,receiver) (itb-lfe:open profile blob)))
    (tuple sender receiver)))

;; Whole-buffer pump through an incremental session with 1 MiB feed /
;; drain slices: begin -> write slices (draining the spool after each
;; write) -> end -> drain until finished -> free.
(defun pump (pipe direction data)
  (let ((`#(ok ,stream) (case direction
                          ('encrypt (itb-lfe:encrypt-stream pipe))
                          ('decrypt (itb-lfe:decrypt-stream pipe)))))
    (let ((acc (feed stream data '())))
      (let ((`ok (itb-lfe:stream-end stream)))
        (let ((out (drain-all stream acc)))
          (let ((`ok (itb-lfe:stream-free stream)))
            out))))))

(defun feed (stream data acc)
  (if (=:= data #"")
    acc
    (let* ((n (erlang:min (byte_size data) (SLICE)))
           (slice (binary:part data 0 n))
           (rest (binary:part data n (- (byte_size data) n)))
           (`ok (itb-lfe:stream-write stream slice))
           ;; A read before end never blocks; drain whatever the chain
           ;; has produced so far to bound the Go-side spool.
           (acc1 (drain-ready stream acc)))
      (feed stream rest acc1))))

(defun drain-ready (stream acc)
  (case (itb-lfe:stream-read stream (SLICE))
    (`#(ok #"" ,_) acc)
    (`#(ok ,piece false) (drain-ready stream (cons piece acc)))
    (`#(ok ,piece true) (cons piece acc))))

(defun drain-all (stream acc)
  (case (itb-lfe:stream-read stream (SLICE))
    (`#(ok ,piece true)
      (iolist_to_binary (lists:reverse (cons piece acc))))
    (`#(ok ,piece false)
      (drain-all stream (cons piece acc)))))

;; Probes successive flip positions until one lands in authenticated
;; content (mac_failure); 'false only if the whole wire is exhausted.
(defun probe-flip (receiver wire pos)
  (if (>= pos (byte_size wire))
    'false
    (case (itb-lfe:decrypt-message receiver (flip-byte wire pos))
      (`#(error #(mac_failure ,_)) 'true)
      ;; A clean decrypt (flip in unauthenticated residue) or a
      ;; structural envelope failure — keep probing for a MAC hit.
      (`#(ok ,_) (probe-flip receiver wire (+ pos 1)))
      (`#(error #(,_ ,_)) (probe-flip receiver wire (+ pos 1))))))

;; Copy of wire with bit 0 of byte pos flipped.
(defun flip-byte (wire pos)
  (let ((head (binary:part wire 0 pos))
        (byte (binary:at wire pos))
        (tail (binary:part wire (+ pos 1) (- (byte_size wire) pos 1))))
    (iolist_to_binary (list head (bxor byte 1) tail))))
