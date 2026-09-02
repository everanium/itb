(ns dev.everanium.itb.clojure.runtime
  "Process-wide Go runtime knobs plus the library version string.

  The Java binding's Runtime class is referenced fully-qualified —
  importing it would collide with the auto-imported
  java.lang.Runtime.")

(def binding-version
  "The binding's own version."
  "0.3.4")

(defn set-memory-limit!
  "Sets the Go runtime's soft heap limit in bytes and returns the
  previous limit. A negative value queries without changing."
  ^long [^long bytes]
  (com.everanium.itb.Runtime/setMemoryLimit bytes))

(defn set-gc-percent!
  "Sets the Go GC trigger percentage and returns the previous value.
  A negative value queries without changing."
  ^long [pct]
  (long (com.everanium.itb.Runtime/setGCPercent (int pct))))

(defn version
  "Returns the libitb library version string."
  ^String []
  (com.everanium.itb.Runtime/version))
