(ns dev.everanium.itb.clojure.stream
  "Incremental stream sessions over an open Pipeline.

  A session is a dumb byte pump: the encrypt side takes plaintext in
  through `write!` and yields wire through `read!`; the decrypt side
  is the mirror (wire in, plaintext out). All chunking, MAC,
  envelope, and wire-format decisions stay inside libitb. Closing a
  session (explicitly, via `with-open`, or by the Java layer's
  Cleaner backstop on GC) cancels it and frees the Go-side state.

  Each session type holds its parent Pipeline record in the `parent`
  field, pinning the pipeline reachable while the session is live."
  (:require [dev.everanium.itb.clojure.error :refer [itb-call]])
  (:import [com.everanium.itb DecryptStream EncryptStream]
           [java.io OutputStream]))

(defprotocol Session
  "Polymorphic surface shared by the encrypt and decrypt session
  types."
  (write! [session src] [session src off len]
    "Feeds bytes into the session (`len` bytes of `src` starting at
    `off` in the 4-arity form). Blocks until the cipher chain accepts
    them; errors are sticky.")
  (end! [session]
    "Signals end-of-input. Idempotent; `write!` after `end!` fails
    with :bad-input.")
  (read! [session dst]
    "Drains up to `(alength dst)` produced bytes into the byte array
    `dst` and returns {:count n :finished? f}. Partial drains are
    normal; a zero count before `end!` means the chain has nothing
    spooled yet. After `end!`, an empty-spool read blocks until the
    terminal bytes arrive or the session errors.")
  (finished? [session]
    "True once a `read!` has reported the session output complete.")
  (session-parent [session]
    "The parent Pipeline record this session runs against."))

(deftype EncryptSession [parent ^EncryptStream impl]
  Session
  (write! [_ src]
    (itb-call (.write impl ^bytes src)))
  (write! [_ src off len]
    (itb-call (.write impl ^bytes src (int off) (int len))))
  (end! [_]
    (itb-call (.end impl)))
  (read! [_ dst]
    (itb-call
     (let [n (.read impl ^bytes dst)]
       {:count n :finished? (.isFinished impl)})))
  (finished? [_]
    (.isFinished impl))
  (session-parent [_] parent)

  java.lang.AutoCloseable
  (close [_] (.close impl)))

(deftype DecryptSession [parent ^DecryptStream impl]
  Session
  (write! [_ src]
    (itb-call (.write impl ^bytes src)))
  (write! [_ src off len]
    (itb-call (.write impl ^bytes src (int off) (int len))))
  (end! [_]
    (itb-call (.end impl)))
  (read! [_ dst]
    (itb-call
     (let [n (.read impl ^bytes dst)]
       {:count n :finished? (.isFinished impl)})))
  (finished? [_]
    (.isFinished impl))
  (session-parent [_] parent)

  java.lang.AutoCloseable
  (close [_] (.close impl)))

(def ^:private copy-buf-size (bit-shift-left 1 20))

(defn copy-to!
  "Calls `end!` (idempotent) and writes every remaining session
  output byte to the java.io.OutputStream `out`, flushing on
  completion."
  [session ^OutputStream out]
  (end! session)
  (let [buf (byte-array copy-buf-size)]
    (loop []
      (let [{n :count fin :finished?} (read! session buf)]
        (when (pos? (long n))
          (.write out buf 0 (int n)))
        (if fin
          (.flush out)
          (recur))))))
