;;;; itb-eitb — command-line demonstrator for the ITB LFE binding,
;;;; ported from the Erlang binding's eitb escript.
;;;;
;;;; Subcommands:
;;;;
;;;;   eitb version                                 library + binding versions
;;;;   eitb hashes                                  shipped hash primitive roster
;;;;   eitb encrypt <profile> <in-file> <out-file>  Single Message encrypt
;;;;   eitb decrypt <profile> <blob-hex> <in-file> <out-file>
;;;;
;;;; `encrypt` prints the session blob to stderr as hex; feed that
;;;; hex back to `decrypt` on the receiving side.
;;;;
;;;; The eitb bash launcher compiles this module with the hex-fetched
;;;; LFE compiler and invokes main/1 with the CLI argument list; the
;;;; compiled binding (./build.sh in bindings/lfe) is resolved by the
;;;; launcher relative to its own location.

(defmodule itb-eitb
  (export (main 1)))

(defmacro EITB-LFE-VERSION () "0.3.0")

(defun main (args)
  (erlang:halt (dispatch args)))

(defun dispatch
  (('("version")) (cmd-version))
  (('("hashes")) (cmd-hashes))
  ((`("encrypt" ,profile ,in-file ,out-file))
    (cmd-encrypt profile in-file out-file))
  ((`("decrypt" ,profile ,blob-hex ,in-file ,out-file))
    (cmd-decrypt profile blob-hex in-file out-file))
  ((_) (usage)))

(defun usage ()
  (io:format 'standard_error
             (++ "usage: eitb version~n"
                 "       eitb hashes~n"
                 "       eitb encrypt <profile> <in-file> <out-file>~n"
                 "       eitb decrypt <profile> <blob-hex> <in-file>"
                 " <out-file>~n")
             '())
  2)

(defun fail (what reason)
  (let ((`#(,status ,detail) reason))
    (io:format 'standard_error "eitb: ~s: ~p: ~s~n"
               (list what status detail))
    1))

;; Defensive Go-runtime pacing for cipher workloads on large files: a
;; soft memory cap + aggressive GC keep the scratch heap bounded. The
;; setter return values report the previous settings, not an error.
(defun cap-go-runtime ()
  (itb-lfe:set-memory-limit (bsl 512 20)) ;; 512 MiB soft cap
  (itb-lfe:set-gc-percent 20)             ;; aggressive GC
  'ok)

(defun cmd-version ()
  (case (itb-lfe:version)
    (`#(ok ,version)
      (io:format "libitb ~s~n" (list version))
      (io:format "itb-lfe ~s~n" (list (EITB-LFE-VERSION)))
      0)
    (`#(error ,reason) (fail "version" reason))))

(defun cmd-hashes ()
  (lists:foldl
    (match-lambda
      ((`#(,name ,width) index)
        (io:format "~2b  ~-12s ~b bits~n" (list index name width))
        (+ index 1)))
    0
    (itb-lfe:hashes))
  0)

;; Profiles whose canonical name begins with "streaming-" route
;; through the streaming session pair instead of the Single Message
;; pair. A one-shot Streaming call opens a session, feeds the whole
;; payload, signals end, and drains until finished.
(defun streaming-profile? (profile)
  (lists:prefix "streaming-" profile))

(defun ensure-parent-dir (path)
  (filelib:ensure_dir path))

(defun stream-one-shot (pipe direction payload)
  (let ((begin-fn (case direction
                    ('encrypt #'itb-lfe:encrypt-stream/1)
                    ('decrypt #'itb-lfe:decrypt-stream/1))))
    (case (funcall begin-fn pipe)
      (`#(error ,reason) `#(error ,reason))
      (`#(ok ,session)
        (let ((result (feed-and-drain session payload)))
          (itb-lfe:stream-free session)
          result)))))

(defun feed-and-drain (session payload)
  (case (itb-lfe:stream-write session payload)
    (`#(error ,reason) `#(error ,reason))
    ('ok
      (case (itb-lfe:stream-end session)
        (`#(error ,reason) `#(error ,reason))
        ('ok (drain-stream session '()))))))

(defun drain-stream (session acc)
  (case (itb-lfe:stream-read session)
    (`#(error ,reason) `#(error ,reason))
    (`#(ok ,piece 'true)
      `#(ok ,(erlang:iolist_to_binary (lists:reverse (cons piece acc)))))
    (`#(ok ,piece 'false)
      (drain-stream session (cons piece acc)))))

(defun cmd-encrypt (profile in-file out-file)
  (cap-go-runtime)
  (case (file:read_file in-file)
    (`#(error ,read-err)
      (io:format 'standard_error "eitb: cannot read ~s: ~p~n"
                 (list in-file read-err))
      1)
    (`#(ok ,plain)
      (case (itb-lfe:init (list_to_binary profile))
        (`#(error ,reason) (fail "init" reason))
        (`#(ok ,pipe)
          (let ((rc (encrypt-with pipe plain profile in-file out-file)))
            (itb-lfe:free pipe)
            rc))))))

(defun encrypt-with (pipe plain profile in-file out-file)
  (let ((result (if (streaming-profile? profile)
                  (stream-one-shot pipe 'encrypt plain)
                  (itb-lfe:encrypt-message pipe plain))))
    (case result
      (`#(error ,reason) (fail "encrypt" reason))
      (`#(ok ,wire)
        (ensure-parent-dir out-file)
        (case (file:write_file out-file wire)
          (`#(error ,write-err)
            (io:format 'standard_error "eitb: cannot write ~s: ~p~n"
                       (list out-file write-err))
            1)
          ('ok
            (let ((`#(ok ,blob) (itb-lfe:blob pipe)))
              (io:format 'standard_error "~s~n"
                         (list (string:lowercase (binary:encode_hex blob))))
              (io:format "encrypted ~s -> ~s (~b -> ~b bytes)~n"
                         (list in-file out-file (byte_size plain)
                               (byte_size wire)))
              0)))))))

(defun cmd-decrypt (profile blob-hex in-file out-file)
  (cap-go-runtime)
  (case (decode-hex blob-hex)
    ('error
      (io:format 'standard_error "eitb: invalid blob hex~n" '())
      1)
    (`#(ok ,blob)
      (case (file:read_file in-file)
        (`#(error ,read-err)
          (io:format 'standard_error "eitb: cannot read ~s: ~p~n"
                     (list in-file read-err))
          1)
        (`#(ok ,wire)
          (decrypt-with profile blob wire in-file out-file))))))

(defun decrypt-with (profile blob wire in-file out-file)
  (case (itb-lfe:open (list_to_binary profile) blob)
    (`#(error ,reason) (fail "open" reason))
    (`#(ok ,pipe)
      (let* ((result (if (streaming-profile? profile)
                       (stream-one-shot pipe 'decrypt wire)
                       (itb-lfe:decrypt-message pipe wire)))
             (rc (case result
                   (`#(error ,dec-err) (fail "decrypt" dec-err))
                   (`#(ok ,plain)
                     (ensure-parent-dir out-file)
                     (case (file:write_file out-file plain)
                       (`#(error ,write-err)
                         (io:format 'standard_error
                                    "eitb: cannot write ~s: ~p~n"
                                    (list out-file write-err))
                         1)
                       ('ok
                         (io:format
                           "decrypted ~s -> ~s (~b -> ~b bytes)~n"
                           (list in-file out-file (byte_size wire)
                                 (byte_size plain)))
                         0))))))
        (itb-lfe:free pipe)
        rc))))

(defun decode-hex (hex)
  (if (andalso (> (length hex) 0) (=:= (rem (length hex) 2) 0))
    (try
      (tuple 'ok (binary:decode_hex (list_to_binary hex)))
      (catch
        (`#(error ,_ ,_) 'error)))
    'error))
