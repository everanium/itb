(ns dev.everanium.itb.clojure.error
  "Error surface shared by every fallible call in the binding.

  A non-OK libitb status surfaces as a `clojure.lang.ExceptionInfo`
  (`ex-info`) whose data map carries:

    :type   ::itb
    :status status keyword (see dev.everanium.itb.clojure.status)
    :code   raw ABI status code (attributable even when :status is
            :unknown)

  The message appends the ITB_LastError diagnostic captured by the
  Java layer immediately after the failing call (process-global
  last-write-wins — under concurrent use the message may belong to a
  different call; the status code is always attributable)."
  (:require [dev.everanium.itb.clojure.status :as status])
  (:import [com.everanium.itb ItbException]))

(defn itb-error?
  "True when `e` is the binding's ex-info error."
  [e]
  (and (instance? clojure.lang.ExceptionInfo e)
       (= ::itb (:type (ex-data e)))))

(defn error-status
  "The status keyword carried by a binding error; nil for anything
  else."
  [e]
  (when (itb-error? e)
    (:status (ex-data e))))

(defn from-exception
  "Translates the Java binding's ItbException into the binding's
  ex-info, mapping the raw ABI code so a code outside the known
  roster surfaces as :unknown rather than collapsing to :internal."
  ^clojure.lang.ExceptionInfo [^ItbException e]
  (let [code (.rawCode e)
        st (status/code->status code)
        msg (or (.getMessage e)
                (str "itb: status=" code " (" (status/label st) ")"))]
    (ex-info msg {:type ::itb :status st :code code} e)))

(defmacro itb-call
  "Runs `body`, translating the Java binding's ItbException into the
  binding's ex-info error."
  [& body]
  `(try
     ~@body
     (catch ItbException e#
       (throw (from-exception e#)))))
