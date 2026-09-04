(ns dev.everanium.itb.clojure.status
  "Status codes mirrored from the libitb C ABI
  (cmd/cshared/internal/capi/errors.go), modelled as namespaced-free
  keywords so call sites match with plain `=` / `case`. Numeric
  values are stable across releases; a code outside the known roster
  (a future libitb release) maps to :unknown while the raw code stays
  available in the error map.")

(def ^:private code-table
  [[0  :ok                   "ok"]
   [1  :bad-hash             "unknown hash name"]
   [2  :bad-key-bits         "invalid key bits"]
   [3  :bad-handle           "invalid handle"]
   [4  :bad-input            "invalid input"]
   [5  :buffer-too-small     "output buffer too small"]
   [6  :encrypt-failed       "encrypt failed"]
   [7  :decrypt-failed       "decrypt failed"]
   [8  :seed-width-mix       "seed width mismatch"]
   [9  :bad-mac              "unknown MAC name or invalid MAC handle"]
   [10 :mac-failure          "MAC verification failed"]
   [11 :blob-malformed-recipe "blob profile record invalid"]
   [12 :recipe-primitive-unknown "blob profile record names a primitive absent from the local registries"]
   [13 :unknown-profile      "unknown profile name"]
   [14 :reserved-14          "reserved status"]
   [15 :reserved-15          "reserved status"]
   [16 :reserved-16          "reserved status"]
   [17 :reserved-17          "reserved status"]
   [19 :blob-mode-mismatch   "blob mode mismatch"]
   [20 :blob-malformed       "malformed state blob"]
   [21 :blob-version-too-new "blob version too new"]
   [22 :blob-too-many-opts   "too many blob export opts"]
   [23 :stream-truncated     "stream truncated before terminator"]
   [24 :stream-after-final   "stream chunk after terminator"]
   [25 :triple-closed        "Triple Pipeline is closed"]
   [26 :profile-exists       "profile name already registered"]
   [99 :internal             "internal error"]])

(def ^:private code->kw
  (into {} (map (fn [[code kw _]] [code kw])) code-table))

(def ^:private kw->code
  (into {} (map (fn [[code kw _]] [kw code])) code-table))

(def ^:private kw->label
  (into {} (map (fn [[_ kw label]] [kw label])) code-table))

(defn code->status
  "Maps a raw libitb status code to its keyword; an unknown code maps
  to :unknown (keep the raw code alongside when reporting)."
  [code]
  (get code->kw code :unknown))

(defn status->code
  "Maps a status keyword back to its numeric ABI code; nil for
  :unknown and unrecognised keywords."
  [status]
  (get kw->code status))

(defn label
  "Short human-readable label for a status keyword."
  [status]
  (get kw->label status "unknown status"))
