(ns io.github.everanium.itb3.clojure.profile
  "Profile record — a Clojure map view over the Java binding's typed
  Triple profile record (io.github.everanium.itb3.Profile), the JSON object
  the blob carries, `inspect` / `lookup` return, and `register!`
  accepts.

  Map keys (every one optional on input; `profile->map` emits all):

    :name        string  — registry handle (\"\" on an anonymous record)
    :mode        string  — e.g. \"streaming-aead\"
    :width       long    — seed width in bits
    :hash        string  — uniform inner hash (\"\" on a mixed profile)
    :hashes      vector of 8 strings — mixed constellation ([] when
                 uniform), slot order [noise lock data1 data2 data3
                 start1 start2 start3]
    :key-bits    long
    :nonce-bits  long or nil — inspection-only (see below)
    :barrier-fill long or nil — inspection-only (see below)
    :mac         string  — \"\" on a No MAC profile
    :tag-stub    long    — 0 when absent
    :chunk       long    — 0 when absent
    :wrapper?    boolean
    :outer       string  — \"\" when absent
    :parallax?   boolean
    :palette     vector of strings ([] when absent)
    :segment     long    — 0 when absent

  :nonce-bits and :barrier-fill are inspection-only. They are not
  part of the profile recipe: `inspect` reads them from the blob's
  runtime globals snapshot, while `lookup` leaves both nil because
  the registry entry never carries them. Go rejects a `register!`
  payload that carries either key, so dissoc both before registering
  an inspected record.

  No semantic validation happens on the JVM side — every field rule
  is enforced by Go at register! / load time and surfaces as the
  binding's ex-info error. An unrecognised map key throws the
  binding's :bad-input error before any FFI call is made."
  (:import [io.github.everanium.itb3 Profile]))

(defn profile->map
  "Converts a Java Profile record into the map shape above."
  [^Profile p]
  {:name (.name p)
   :mode (.mode p)
   :width (.width p)
   :hash (.hash p)
   :hashes (vec (.hashes p))
   :key-bits (.keyBits p)
   :nonce-bits (some-> (.nonceBits p) long)
   :barrier-fill (some-> (.barrierFill p) long)
   :mac (.mac p)
   :tag-stub (.tagStub p)
   :chunk (.chunk p)
   :wrapper? (.wrapper p)
   :outer (.outer p)
   :parallax? (.parallax p)
   :palette (vec (.palette p))
   :segment (.segment p)})

(defn map->profile
  "Converts a map in the shape above (or a Java Profile, passed
  through) into a Java Profile record."
  ^Profile [m]
  (if (instance? Profile m)
    m
    (let [p (Profile.)]
      (doseq [[k v] m]
        (case k
          :name (.name p (str v))
          :mode (.mode p (str v))
          :width (.width p (int v))
          :hash (.hash p (str v))
          :hashes (.hashes p ^"[Ljava.lang.String;" (into-array String (map str v)))
          :key-bits (.keyBits p (int v))
          :nonce-bits (.nonceBits p (some-> v int))
          :barrier-fill (.barrierFill p (some-> v int))
          :mac (.mac p (str v))
          :tag-stub (.tagStub p (int v))
          :chunk (.chunk p (int v))
          :wrapper? (.wrapper p (boolean v))
          :outer (.outer p (str v))
          :parallax? (.parallax p (boolean v))
          :palette (.palette p ^"[Ljava.lang.String;" (into-array String (map str v)))
          :segment (.segment p (int v))
          (throw (ex-info (str "itb: unknown profile key " k)
                          {:type :io.github.everanium.itb3.clojure.error/itb
                           :status :bad-input
                           :code 4
                           :key k}))))
      p)))
