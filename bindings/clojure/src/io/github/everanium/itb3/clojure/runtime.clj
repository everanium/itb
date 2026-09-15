(ns io.github.everanium.itb3.clojure.runtime
  "Process-wide Go runtime knobs plus the library version string.

  The Java binding's Runtime class is referenced fully-qualified —
  importing it would collide with the auto-imported
  java.lang.Runtime.")

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

(defn version
  "Returns the libitb3 library version string."
  ^String []
  (io.github.everanium.itb3.Runtime/version))
