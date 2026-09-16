(ns io.github.everanium.itb3.clojure.runtime
  "Process-wide Go runtime knobs, runtime diagnostics, and the library
  version string.

  The Java binding's Runtime class is referenced fully-qualified —
  importing it would collide with the auto-imported
  java.lang.Runtime."
  (:require [io.github.everanium.itb3.clojure.error :refer [itb-call]]))

(def binding-version
  "The binding's own version."
  "0.5.1")

(defn set-memory-limit!
  "Sets the Go runtime's soft heap limit in bytes and returns the
  previous limit. A negative value queries without changing."
  ^long [^long bytes]
  (io.github.everanium.itb3.Runtime/setMemoryLimit bytes))

(defn set-gc-percent!
  "Sets the Go GC trigger percentage and returns the previous value.
  A negative value queries without changing."
  ^long [pct]
  (long (io.github.everanium.itb3.Runtime/setGCPercent (int pct))))

(defn set-gomaxprocs!
  "Sets the Go runtime's GOMAXPROCS and returns the previous value.
  Zero or a negative value queries without changing."
  ^long [n]
  (long (io.github.everanium.itb3.Runtime/setGOMAXPROCS (int n))))

(defn write-heap-profile!
  "Writes the Go runtime's heap profile (pprof format) to `path` after
  one forced garbage collection. An empty path falls back to the
  ITB_MEMPROFILE environment variable inside libitb3; a path that is
  still empty, or a file-system failure, fails with :bad-input."
  [path]
  (itb-call (io.github.everanium.itb3.Runtime/writeHeapProfile ^String (str path))))

(defn pool-stats-len
  "The number of long slots `pool-stats` fills."
  ^long []
  (long (io.github.everanium.itb3.Runtime/poolStatsLen)))

(defn pool-stats
  "One snapshot of the library's pool hit / miss counters, as a long
  array. Every counter is a monotonically increasing total since
  library load, so a per-window figure is the difference of two
  snapshots.

  Slot layout, with T the tier count in slot 0: hash-array tier i
  holds starter width, checkouts, constructor misses, regrow
  replacements and bytes allocated at slots 1 + 5*i .. 1 + 5*i + 4;
  the scratch byte pool's get / new / regrow / regrow-bytes follow at
  1 + 5*T, and the parallax chunk pool's at 1 + 5*T + 4. The vector
  is sized from `pool-stats-len`, never from a constant — the tier
  ladder is a library-side policy that grows."
  ^longs []
  (itb-call (io.github.everanium.itb3.Runtime/poolStats)))

(defn version
  "Returns the libitb3 library version string."
  ^String []
  (io.github.everanium.itb3.Runtime/version))
