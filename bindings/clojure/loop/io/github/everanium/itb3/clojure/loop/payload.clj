(ns io.github.everanium.itb3.clojure.loop.payload
  "Plaintext content: the payload modes, the seeded per-worker
  generator, and the buffer fill from the operating-system CSPRNG."
  (:import [java.security SecureRandom]
           [java.util.function Supplier]))

(def payload-modes
  "Payload mode selector values for the --payload-mode flag, keyed by
  the label the flag accepts.

    fixed          one CSPRNG-generated buffer per worker, held
                   unchanged for the whole run (the default)
    rotating       the buffer is regenerated before every iteration,
                   so no two encrypt calls see the same plaintext
    pattern-zero   every byte 0x00
    pattern-ff     every byte 0xFF — the two degenerate constant fills
                   probing minimum-entropy plaintext handling
    pattern-ascii  a repeating 'A'..'Z' ramp probing low-entropy
                   structured text"
  {"fixed" :fixed
   "rotating" :rotating
   "pattern-zero" :pattern-zero
   "pattern-ff" :pattern-ff
   "pattern-ascii" :pattern-ascii})

(def mode-label
  "The flag spelling of a payload mode keyword."
  (into {} (map (fn [[label kw]] [kw label])) payload-modes))

(defn parse-mode
  "The mode keyword for a flag value; nil when the value is outside
  the roster."
  [s]
  (get payload-modes s))

(def ^:private ^ThreadLocal csprng
  "The operating-system CSPRNG, one instance per calling thread so
  concurrent payload refills never serialise on one provider."
  (ThreadLocal/withInitial (reify Supplier (get [_] (SecureRandom.)))))

(defn seed-worker
  "Seeded plaintext. The seed makes plaintext content reproducible so
  a failing iteration can be replayed with the same bytes; it governs
  nothing else — pipeline keys, nonces and masters stay CSPRNG-drawn,
  so a seeded run is a reproduction aid and never a security test.
  Each worker's stream is domain-separated by its id so seeded workers
  still hold pairwise-distinct buffers under the fixed and rotating
  modes. The generator is splitmix64: a few lines in any language,
  which is why it is the one every binding uses."
  ^longs [^long seed ^long worker-id]
  (long-array 1 (unchecked-add seed (unchecked-inc worker-id))))

(defn- splitmix64
  "Advances the one-slot generator state in place and returns the next
  output word.

  Clojure-specific. A long is immutable and a local cannot be mutated
  across a call, so the state lives in a one-element long array the
  worker owns."
  ^long [^longs state]
  (let [s (unchecked-add (aget state 0) -7046029254386353131)] ; 0x9E3779B97F4A7C15
    (aset state 0 s)
    (let [z (unchecked-multiply (bit-xor s (unsigned-bit-shift-right s 30))
                                -4658895280553007687) ; 0xBF58476D1CE4E5B9
          z (unchecked-multiply (bit-xor z (unsigned-bit-shift-right z 27))
                                -7723592293110705685)] ; 0x94D049BB133111EB
      (bit-xor z (unsigned-bit-shift-right z 31)))))

(defn fill-random
  "Fills `buf` from the operating-system CSPRNG.

  Clojure-specific. The JDK's default SecureRandom provider on this
  platform draws from /dev/urandom through a file descriptor rather
  than through the glibc getrandom entry, and the platform offers no
  supported way for a JVM source set to reach that entry — a native
  declaration of its own is exactly the reach past the binding the
  utility must not make. One draw still happens per fill; it is
  observable as a read on that descriptor rather than as a getrandom
  call."
  [^bytes buf]
  (.nextBytes ^SecureRandom (.get csprng) buf)
  true)

(defn fill-payload
  "Writes one plaintext buffer according to the payload mode. The
  fixed and rotating modes draw from the seeded generator when the run
  is seeded and from the OS CSPRNG otherwise; the pattern modes are
  deterministic regardless of the seed. False when the CSPRNG fails."
  [mode seeded? ^longs rng ^bytes buf]
  (case mode
    (:fixed :rotating)
    (if-not seeded?
      (fill-random buf)
      (let [n (alength buf)]
        (loop [i 0]
          (if (>= i n)
            true
            (let [v (splitmix64 rng)
                  k (min 8 (- n i))]
              (dotimes [j k]
                (aset-byte buf (+ i j)
                           (unchecked-byte (unsigned-bit-shift-right v (* 8 j)))))
              (recur (+ i 8)))))))

    :pattern-zero
    (do (java.util.Arrays/fill buf (byte 0)) true)

    :pattern-ff
    (do (java.util.Arrays/fill buf (unchecked-byte 0xFF)) true)

    :pattern-ascii
    (let [n (alength buf)]
      (dotimes [i n]
        (aset-byte buf i (unchecked-byte (+ (int \A) (rem i 26)))))
      true)))
