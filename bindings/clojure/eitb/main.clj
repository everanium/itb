;; eitb — command-line demonstrator for the ITB Clojure binding.
;;
;; Subcommands:
;;
;;   eitb version                                   library + binding versions
;;   eitb profiles                                  registered profile catalogue
;;   eitb encrypt <profile> <in-file> <out-file>    Single Message encrypt
;;   eitb decrypt <profile> <blob-hex> <in-file> <out-file>
;;
;; `encrypt` prints the session blob to stderr as hex; feed that hex
;; back to `decrypt` on the receiving side. `profiles` lists the
;; registered profile catalogue one name per line; the profiles that
;; carry a cipher surface are the ones `encrypt` / `decrypt` accept.
;;
;; Loaded as a clojure.main script by the sibling `eitb` launcher:
;;
;;   clojure -M:eitb eitb/main.clj <args>

(ns dev.everanium.itb.clojure.eitb-main
  (:require [clojure.java.io :as io]
            [clojure.string :as string]
            [dev.everanium.itb.clojure.core :as itb]
            [dev.everanium.itb.clojure.runtime :as runtime])
  (:import [java.nio.file Files]
           [java.util HexFormat]))

(defn- read-file ^bytes [path]
  (Files/readAllBytes (.toPath (io/file path))))

(defn- ensure-parent-dir!
  "Create the parent directory of `path` recursively (mkdir -p)."
  [path]
  (when-let [parent (.getParentFile (io/file path))]
    (.mkdirs parent)))

(defn- write-file [path ^bytes data]
  (ensure-parent-dir! path)
  (with-open [out (io/output-stream (io/file path))]
    (.write out data)))

(defn- streaming-profile?
  "Profiles whose canonical name begins with `streaming-` route
  through the one-shot streaming buffered pair instead of the Single
  Message pair."
  [profile]
  (string/starts-with? profile "streaming-"))

(defn- hex ^String [^bytes data]
  (.formatHex (HexFormat/of) data))

(defn- unhex
  "Tolerant hex parse: whitespace stripped, optional 0x prefix,
  case-insensitive."
  ^bytes [s]
  (let [s (-> s
              (string/replace #"\s" "")
              (string/replace #"^0[xX]" ""))]
    (.parseHex (HexFormat/of) ^String s)))

(defn- cmd-version []
  (println (str "libitb " (runtime/version)))
  (println (str "itb-clojure " runtime/binding-version))
  0)

(defn- cmd-profiles
  "Prints the registered profile catalogue one name per line in the
  sorted order `profiles` returns."
  []
  (run! println (itb/profiles))
  0)

(defn- cmd-encrypt [profile in-file out-file]
  (let [plain (read-file in-file)]
    (with-open [pipe (itb/init profile)]
      (let [wire (if (streaming-profile? profile)
                   (itb/encrypt-stream-one-shot pipe plain)
                   (itb/encrypt-message pipe plain))]
        (write-file out-file wire)
        (binding [*out* *err*]
          (println (hex (itb/save pipe)))
          (flush))
        (println (str "encrypted " in-file " -> " out-file
                      " (" (alength ^bytes plain) " -> " (alength ^bytes wire) " bytes)")))))
  0)

(defn- cmd-decrypt [profile blob-hex in-file out-file]
  (let [blob (unhex blob-hex)
        wire (read-file in-file)]
    (with-open [pipe (itb/load blob)]
      (let [plain (if (streaming-profile? profile)
                    (itb/decrypt-stream-one-shot pipe wire)
                    (itb/decrypt-message pipe wire))]
        (write-file out-file plain)
        (println (str "decrypted " in-file " -> " out-file
                      " (" (alength ^bytes wire) " -> " (alength ^bytes plain) " bytes)")))))
  0)

(defn- usage []
  (binding [*out* *err*]
    (println "usage: eitb version")
    (println "       eitb profiles")
    (println "       eitb encrypt <profile> <in-file> <out-file>")
    (println "       eitb decrypt <profile> <blob-hex> <in-file> <out-file>")
    (flush))
  2)

(defn -main [& args]
  ;; Defensive Go-runtime pacing caps — the CLI can be pointed at
  ;; gigabyte files.
  (runtime/set-memory-limit! (bit-shift-left 512 20))
  (runtime/set-gc-percent! 20)
  (let [[cmd & more] args
        rc (try
             (cond
               (and (= cmd "version") (empty? more)) (cmd-version)
               (and (= cmd "profiles") (empty? more)) (cmd-profiles)
               (and (= cmd "encrypt") (= 3 (count more))) (apply cmd-encrypt more)
               (and (= cmd "decrypt") (= 4 (count more))) (apply cmd-decrypt more)
               :else (usage))
             (catch Exception e
               (binding [*out* *err*]
                 (println (str "eitb: " (ex-message e)))
                 (flush))
               1))]
    (flush)
    (System/exit rc)))

(apply -main *command-line-args*)
