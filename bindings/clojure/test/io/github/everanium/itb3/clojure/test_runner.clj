(ns io.github.everanium.itb3.clojure.test-runner
  "clojure.test harness entry: runs the whole suite and exits
  non-zero on any failure or error.

  Invocation (run_tests.sh does this):

    clojure -M:test -m io.github.everanium.itb3.clojure.test-runner

  Optional arguments narrow the run to the named test namespaces
  (short suffix form, e.g. `smoke-test errors-test`)."
  (:require [clojure.string :as str]
            [clojure.test :as t]
            [io.github.everanium.itb3.clojure.errors-test]
            [io.github.everanium.itb3.clojure.inner-hashes-test]
            [io.github.everanium.itb3.clojure.message-test]
            [io.github.everanium.itb3.clojure.persist-test]
            [io.github.everanium.itb3.clojure.rekey-test]
            [io.github.everanium.itb3.clojure.smoke-test]
            [io.github.everanium.itb3.clojure.stream-cancel-test]
            [io.github.everanium.itb3.clojure.stream-incremental-test]
            [io.github.everanium.itb3.clojure.stream-pump-test]
            [io.github.everanium.itb3.clojure.stream-sticky-test]))

(def ^:private suite
  '[io.github.everanium.itb3.clojure.smoke-test
    io.github.everanium.itb3.clojure.message-test
    io.github.everanium.itb3.clojure.stream-pump-test
    io.github.everanium.itb3.clojure.stream-incremental-test
    io.github.everanium.itb3.clojure.stream-sticky-test
    io.github.everanium.itb3.clojure.stream-cancel-test
    io.github.everanium.itb3.clojure.rekey-test
    io.github.everanium.itb3.clojure.errors-test
    io.github.everanium.itb3.clojure.inner-hashes-test
    io.github.everanium.itb3.clojure.persist-test])

(defn -main [& args]
  (let [wanted (if (seq args)
                 (let [names (set args)]
                   (filterv #(names (last (str/split (name %) #"\.")))
                            suite))
                 suite)
        _ (when (empty? wanted)
            (binding [*out* *err*]
              (println "test-runner: no namespace matches" (vec args)))
            (System/exit 2))
        result (apply t/run-tests wanted)]
    (flush)
    (System/exit (if (and (zero? (long (:fail result)))
                          (zero? (long (:error result))))
                   0
                   1))))
