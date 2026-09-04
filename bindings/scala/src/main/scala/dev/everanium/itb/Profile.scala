// Profile record — the Java binding's typed view of the Triple
// profile JSON object, re-exported under the Scala package.
//
// The record is a plain data holder plus a JSON codec over the
// fourteen wire keys (name, mode, width, hash, hashes, keybits, mac,
// tagstub, chunk, wrapper, outer, parallax, palette, segment). No
// semantic validation happens on the JVM side — every field rule is
// enforced by Go at Pipeline.register / Pipeline.load time and
// surfaces as ItbError.

package dev.everanium.itb

/** A Triple Pipeline profile record — the type [[Pipeline.inspect]]
  * and [[Pipeline.lookup]] return and [[Pipeline.register]] accepts.
  * Fluent setters chain (`Profile().mode("singlemsg-nomac").width(512)`).
  */
type Profile = com.everanium.itb.Profile

object Profile:
  /** An empty record; populate through the fluent setters. */
  def apply(): Profile = new com.everanium.itb.Profile()
