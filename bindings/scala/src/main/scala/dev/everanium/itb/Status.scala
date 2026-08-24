// Status codes mirrored from the libitb C ABI. Numeric values are
// stable across releases; the Java binding surfaces them unchanged.

package dev.everanium.itb

/** Structural status code carried by every failing libitb call. */
enum Status(val code: Int):
  case Ok extends Status(0)
  case BadHash extends Status(1)
  case BadKeyBits extends Status(2)
  case BadHandle extends Status(3)
  case BadInput extends Status(4)
  case BufferTooSmall extends Status(5)
  case EncryptFailed extends Status(6)
  case DecryptFailed extends Status(7)
  case SeedWidthMix extends Status(8)
  case BadMac extends Status(9)
  case MacFailure extends Status(10)
  case BlobModeMismatch extends Status(19)
  case BlobMalformed extends Status(20)
  case BlobVersionTooNew extends Status(21)
  case BlobTooManyOpts extends Status(22)
  case StreamTruncated extends Status(23)
  case StreamAfterFinal extends Status(24)
  case TripleClosed extends Status(25)
  case ProfileExists extends Status(26)
  case Internal extends Status(99)

object Status:
  private val byCode: Map[Int, Status] =
    Status.values.map(s => s.code -> s).toMap

  /** Maps a raw libitb return code to the enum; codes without a
    * named constant (reserved ranges, future additions) map to
    * [[Status.Internal]] — the raw code stays available on the
    * [[ItbError]] that carries it.
    */
  def fromCode(code: Int): Status = byCode.getOrElse(code, Internal)
