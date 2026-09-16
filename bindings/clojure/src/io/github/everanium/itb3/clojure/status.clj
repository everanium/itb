(ns io.github.everanium.itb3.clojure.status
  "Status codes mirrored from the libitb3 C ABI
  (cmd/cshared/internal/capi/errors.go), modelled as namespaced-free
  keywords so call sites match with plain `=` / `case`. Numeric
  values are stable across releases; a code outside the known roster
  (a future libitb3 release) maps to :unknown while the raw code stays
  available in the error map.

  The keywords are the structural code only. The human wording of a
  failure arrives already composed in the library's own diagnostic —
  the class of failure and, where there is one, the specific case —
  so no wording is restated here.")

(def ^:private code-table
  [[0  :ok]
   [1  :bad-hash]
   [2  :bad-key-bits]
   [3  :bad-handle]
   [4  :bad-input]
   [5  :buffer-too-small]
   [6  :encrypt-failed]
   [7  :decrypt-failed]
   [8  :seed-width-mix]
   [9  :bad-mac]
   [10 :mac-failure]
   [11 :blob-malformed-recipe]
   [12 :recipe-primitive-unknown]
   [13 :unknown-profile]
   [14 :reserved-14]
   [15 :reserved-15]
   [16 :reserved-16]
   [17 :reserved-17]
   [19 :blob-mode-mismatch]
   [20 :blob-malformed]
   [21 :blob-version-too-new]
   [22 :blob-too-many-opts]
   [23 :stream-truncated]
   [24 :stream-after-final]
   [25 :triple-closed]
   [26 :profile-exists]
   [99 :internal]])

(def ^:private code->kw
  (into {} (map (fn [[code kw]] [code kw])) code-table))

(def ^:private kw->code
  (into {} (map (fn [[code kw]] [kw code])) code-table))

(defn code->status
  "Maps a raw libitb3 status code to its keyword; an unknown code maps
  to :unknown (keep the raw code alongside when reporting)."
  [code]
  (get code->kw code :unknown))

(defn status->code
  "Maps a status keyword back to its numeric ABI code; nil for
  :unknown and unrecognised keywords."
  [status]
  (get kw->code status))
