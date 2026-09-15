// Profile record — the Java binding's typed view of the Triple
// profile JSON object, re-exported under the Kotlin package.
//
// The record is a plain data holder plus a JSON codec over the wire
// keys. nonce_bits and barrier_fill are inspection-only —
// Pipeline.inspect populates them from the blob's runtime globals and
// Pipeline.lookup leaves both null. No semantic validation happens on
// the JVM side — every field rule is enforced by Go at
// Pipeline.register / Pipeline.load time and surfaces as
// ItbException.

package io.github.everanium.itb3.kotlin

/**
 * A Triple Pipeline profile record — the type [Pipeline.inspect] and
 * [Pipeline.lookup] return and [Pipeline.register] accepts. Fluent
 * setters chain (`Profile().mode("singlemsg-nomac").width(512)`).
 */
typealias Profile = io.github.everanium.itb3.Profile

/** DSL constructor for [Profile]. */
fun profile(block: Profile.() -> Unit): Profile = Profile().apply(block)
