// Idiomatic Scala lifetime + error surface over the Java binding's
// Triple Pipeline.

package dev.everanium.itb

import java.io.{InputStream, OutputStream}

import com.everanium.itb.Pipeline as JPipeline

import ItbError.attempt

/** Result of one stream drain call: `count` bytes were placed into
  * the destination buffer; `finished` marks the session output as
  * complete.
  */
final case class ReadResult(count: Int, finished: Boolean)

/** A Triple Pipeline session plus its exported blob bytes.
  *
  * The blob carries the session bundle the receiver feeds to
  * [[Pipeline.open]]; [[rekey]] refreshes it. `close()` releases the
  * native handle (libitb zeroes key material internally), so the
  * class composes with `scala.util.Using.resource`; the Java
  * binding's finalization backstop reclaims an unclosed Pipeline.
  *
  * Every fallible operation returns `Either[ItbError, _]`; the
  * for-comprehension is the intended composition style. Callers
  * preferring exceptions can `fold(throw _, identity)` — the error
  * value is a `RuntimeException`.
  *
  * Streaming-decrypt caveat: chunked Streaming AEAD verifies per
  * chunk, so plaintext of verified chunks is released before a later
  * chunk can fail authentication.
  */
final class Pipeline private (private[itb] val underlying: JPipeline)
    extends AutoCloseable:

  /** The exported session bundle bytes for the receiver side. */
  def blob: Array[Byte] = underlying.blob()

  /** Rotates the parallax + wrapper masters and refreshes [[blob]].
    * Must not run concurrently with cipher calls or open stream
    * sessions on the same Pipeline.
    */
  def rekey(permMaster: Array[Byte], wrapMaster: Array[Byte]): Either[ItbError, Unit] =
    attempt(underlying.rekey(permMaster, wrapMaster))

  /** Zeroes the Pipeline's key material and marks it closed.
    * Idempotent; subsequent cipher calls fail with
    * [[Status.TripleClosed]]. The native handle itself is released
    * by [[close]].
    */
  def closeSession(): Either[ItbError, Unit] = attempt(underlying.destroy())

  /** Single Message encrypt: one call, one self-contained wire. */
  def encryptMessage(plaintext: Array[Byte]): Either[ItbError, Array[Byte]] =
    attempt(underlying.encryptMessage(plaintext))

  /** Receive-side counterpart of [[encryptMessage]]. */
  def decryptMessage(wire: Array[Byte]): Either[ItbError, Array[Byte]] =
    attempt(underlying.decryptMessage(wire))

  /** One-shot stream encrypt for callers holding the whole plaintext
    * in memory. For bounded-memory streaming use
    * [[beginEncryptStream]] / [[encryptStreamPump]].
    */
  def encryptStreamOneShot(plaintext: Array[Byte]): Either[ItbError, Array[Byte]] =
    attempt(underlying.encryptStreamOneShot(plaintext))

  /** Receive-side counterpart of [[encryptStreamOneShot]]. */
  def decryptStreamOneShot(wire: Array[Byte]): Either[ItbError, Array[Byte]] =
    attempt(underlying.decryptStreamOneShot(wire))

  /** Opens an incremental encrypt session (plaintext in, wire out).
    * The session holds a reference to this Pipeline, keeping it
    * reachable while the session is live.
    */
  def beginEncryptStream(): Either[ItbError, EncryptStream] =
    attempt(new EncryptStream(this, underlying.encryptStream()))

  /** Opens an incremental decrypt session (wire in, plaintext out).
    * The session holds a reference to this Pipeline, keeping it
    * reachable while the session is live.
    */
  def beginDecryptStream(): Either[ItbError, DecryptStream] =
    attempt(new DecryptStream(this, underlying.decryptStream()))

  /** Pumps `source` through an encrypt session into `destination`
    * with bounded memory: feed a block, drain available wire,
    * repeat; end + final drain on source EOF. The session is freed
    * on return.
    */
  def encryptStreamPump(source: InputStream, destination: OutputStream): Either[ItbError, Unit] =
    attempt(underlying.encryptStreamPump(source, destination))

  /** Receive-side counterpart of [[encryptStreamPump]]. */
  def decryptStreamPump(source: InputStream, destination: OutputStream): Either[ItbError, Unit] =
    attempt(underlying.decryptStreamPump(source, destination))

  /** Releases the native handle. Idempotent. */
  override def close(): Unit = underlying.close()

object Pipeline:

  /** Constructs a fresh Pipeline against the named profile. */
  def init(profile: String, opts: Opts = Opts.empty): Either[ItbError, Pipeline] =
    attempt(new Pipeline(JPipeline.init(profile, opts.toJava)))

  /** Reconstructs a Pipeline from a blob produced by [[init]] or
    * [[Pipeline.rekey]], using the blob-embedded masters. See
    * [[openWithMasters]] to override them.
    */
  def open(profile: String, blob: Array[Byte], opts: Opts = Opts.empty): Either[ItbError, Pipeline] =
    attempt(new Pipeline(JPipeline.open(profile, blob, opts.toJava)))

  /** [[open]] with explicit (non-empty) parallax + wrapper masters
    * overriding the blob-embedded ones; both must be supplied.
    */
  def openWithMasters(
      profile: String,
      blob: Array[Byte],
      opts: Opts,
      permMaster: Array[Byte],
      wrapMaster: Array[Byte]
  ): Either[ItbError, Pipeline] =
    attempt(new Pipeline(JPipeline.open(profile, blob, opts.toJava, permMaster, wrapMaster)))

  /** Registers a user-defined Triple profile under `name` so
    * subsequent [[init]] / [[open]] calls resolve it. The opts
    * follow the register-profile grammar validated by Go — build
    * them with [[Opts.withRaw]] plus the typed setters where key
    * names coincide. A duplicate name fails with
    * [[Status.ProfileExists]].
    */
  def registerProfile(name: String, opts: Opts): Either[ItbError, Unit] =
    attempt(JPipeline.registerProfile(name, opts.toJava))
