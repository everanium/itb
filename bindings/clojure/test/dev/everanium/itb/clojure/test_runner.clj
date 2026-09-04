(ns dev.everanium.itb.clojure.test-runner
  "clojure.test harness entry: runs the whole suite and exits
  non-zero on any failure or error.

  Invocation (run_tests.sh does this):

    clojure -M:test -m dev.everanium.itb.clojure.test-runner

  Optional arguments narrow the run to the named test namespaces
  (short suffix form, e.g. `smoke-test errors-test`)."
  (:require [clojure.string :as str]
            [clojure.test :as t]
            [dev.everanium.itb.clojure.errors-test]
            [dev.everanium.itb.clojure.inner-hashes-test]
            [dev.everanium.itb.clojure.message-test]
            [dev.everanium.itb.clojure.persist-test]
            [dev.everanium.itb.clojure.rekey-test]
            [dev.everanium.itb.clojure.smoke-test]
            [dev.everanium.itb.clojure.stream-cancel-test]
            [dev.everanium.itb.clojure.stream-incremental-test]
            [dev.everanium.itb.clojure.stream-pump-test]
            [dev.everanium.itb.clojure.stream-sticky-test]))

(def ^:private suite
  '[dev.everanium.itb.clojure.smoke-test
    dev.everanium.itb.clojure.message-test
    dev.everanium.itb.clojure.stream-pump-test
    dev.everanium.itb.clojure.stream-incremental-test
    dev.everanium.itb.clojure.stream-sticky-test
    dev.everanium.itb.clojure.stream-cancel-test
    dev.everanium.itb.clojure.rekey-test
    dev.everanium.itb.clojure.errors-test
    dev.everanium.itb.clojure.inner-hashes-test
    dev.everanium.itb.clojure.persist-test])

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
