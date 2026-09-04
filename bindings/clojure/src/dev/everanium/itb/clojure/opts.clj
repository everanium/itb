(ns dev.everanium.itb.clojure.opts
  "Options — a Clojure map rendered onto the Java binding's URL-query
  Opts builder.

  No validation happens here beyond the keyword roster below — every
  value is rendered into a percent-encoded query string by the Java
  layer and passed through to Go verbatim; libitb rejects unknown
  keys or bad values with a diagnostic surfaced as the binding's
  ex-info error. Primitive / MAC / cipher / palette names are opaque
  strings.

  Recognised keys:

    :perm-master            byte array — parallax master override
    :wrap-master            byte array — wrapper master override
    :parallax?              boolean
    :wrapper?               boolean
    :max-workers            long
    :nonce-bits             long
    :barrier-fill           long
    :chunk-size             long
    :key-bits               long
    :parallax-segment-size  long
    :mac-name               string
    :inner-hash             string
    :inner-hashes           seq of strings — per-call constellation
                            override mirroring the Go-side
                            Opts.MixedHashes [8]string field; the 8
                            slot names in the order [noise, lock,
                            data1, data2, data3, start1, start2,
                            start3] are comma-joined into the
                            \"innerHashes\" pass-through key. Fail-fast
                            validation surfaces at Init on the Go side;
                            a typo'd slot or width mismatch surfaces
                            with an error naming the offending slot.
                            When both this and :inner-hash are set,
                            the mixed override wins on the Go side.
    :outer-cipher           string
    :parallax-palette       seq of strings (comma-joined)
    :raw                    map (or seq of pairs) of raw key=value
                            pass-through entries — covers every key
                            the Go side accepts"
  (:import [com.everanium.itb Opts]))

(defn- raw-key ^String [k]
  (if (keyword? k) (name k) (str k)))

(defn build
  "Renders an opts map (possibly nil / empty — pure profile defaults)
  onto a fresh Java Opts builder. An unrecognised keyword throws the
  binding's :bad-input error before any FFI call is made."
  ^Opts [m]
  (let [o (Opts.)]
    (doseq [[k v] m]
      (case k
        :perm-master (.withPermMaster o ^bytes v)
        :wrap-master (.withWrapMaster o ^bytes v)
        :parallax? (.withParallax o (boolean v))
        :wrapper? (.withWrapper o (boolean v))
        :max-workers (.withMaxWorkers o (long v))
        :nonce-bits (.withNonceBits o (long v))
        :barrier-fill (.withBarrierFill o (long v))
        :chunk-size (.withChunkSize o (long v))
        :key-bits (.withKeyBits o (long v))
        :parallax-segment-size (.withParallaxSegmentSize o (long v))
        :mac-name (.withMacName o (str v))
        :inner-hash (.withInnerHash o (str v))
        :inner-hashes (.withInnerHashes o ^"[Ljava.lang.String;" (into-array String (map str v)))
        :outer-cipher (.withOuterCipher o (str v))
        :parallax-palette (.withParallaxPalette o ^"[Ljava.lang.String;" (into-array String (map str v)))
        :raw (doseq [[rk rv] v] (.withRaw o (raw-key rk) (str rv)))
        (throw (ex-info (str "itb: unknown opts key " k
                             " (use :raw for pass-through keys)")
                        {:type :dev.everanium.itb.clojure.error/itb
                         :status :bad-input
                         :code 4
                         :key k}))))
    o))
