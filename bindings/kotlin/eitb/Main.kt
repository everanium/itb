// eitb — command-line demonstrator for the ITB Kotlin binding.
//
// Subcommands:
//
//   eitb version                                   library + binding versions
//   eitb profiles                                  registered profile catalogue
//   eitb encrypt <profile> <in-file> <out-file>    Single Message encrypt
//   eitb decrypt <profile> <blob-hex> <in-file> <out-file>
//
// `encrypt` prints the session blob to stderr as hex; feed that hex
// back to `decrypt` on the receiving side. `profiles` lists the
// registered profile catalogue one name per line; the profiles that
// carry a cipher surface are the ones `encrypt` / `decrypt` accept.

package com.everanium.itb.kotlin.eitb

import com.everanium.itb.kotlin.ItbException
import com.everanium.itb.kotlin.ItbRuntime
import com.everanium.itb.kotlin.Pipeline
import java.io.File
import kotlin.system.exitProcess

fun main(args: Array<String>) {
    // Defensive Go-runtime pacing caps — the CLI can be pointed at
    // gigabyte files.
    ItbRuntime.setMemoryLimit(512L shl 20)
    ItbRuntime.setGCPercent(20)
    try {
        val rc = when {
            args.firstOrNull() == "version" && args.size == 1 -> cmdVersion()
            args.firstOrNull() == "profiles" && args.size == 1 -> cmdProfiles()
            args.firstOrNull() == "encrypt" && args.size == 4 ->
                cmdEncrypt(args[1], args[2], args[3])
            args.firstOrNull() == "decrypt" && args.size == 5 ->
                cmdDecrypt(args[1], args[2], args[3], args[4])
            else -> {
                System.err.println(
                    """
                    usage: eitb version
                           eitb profiles
                           eitb encrypt <profile> <in-file> <out-file>
                           eitb decrypt <profile> <blob-hex> <in-file> <out-file>
                    """.trimIndent(),
                )
                2
            }
        }
        exitProcess(rc)
    } catch (e: ItbException) {
        System.err.println("eitb: ${e.message}")
        exitProcess(1)
    } catch (e: Exception) {
        System.err.println("eitb: ${e.message}")
        exitProcess(1)
    }
}

private fun cmdVersion(): Int {
    println("libitb ${ItbRuntime.version()}")
    println("itb-kotlin ${ItbRuntime.BINDING_VERSION}")
    return 0
}

// Prints the registered profile catalogue one name per line in the
// sorted order Pipeline.profiles() returns.
private fun cmdProfiles(): Int {
    Pipeline.profiles().forEach(::println)
    return 0
}

// Profiles whose canonical name begins with "streaming-" route
// through the one-shot streaming buffered pair instead of the Single
// Message pair.
private fun isStreamingProfile(profile: String): Boolean =
    profile.startsWith("streaming-")

// Recursively create the parent directory of [path] (mkdir -p).
private fun ensureParentDir(path: String) {
    File(path).absoluteFile.parentFile?.mkdirs()
}

private fun cmdEncrypt(profile: String, inFile: String, outFile: String): Int {
    val plain = File(inFile).readBytes()
    Pipeline.init(profile).use { pipe ->
        val wire = if (isStreamingProfile(profile)) {
            pipe.encryptStreamOneShot(plain)
        } else {
            pipe.encryptMessage(plain)
        }
        ensureParentDir(outFile)
        File(outFile).writeBytes(wire)
        System.err.println(toHex(pipe.save()))
        println("encrypted $inFile -> $outFile (${plain.size} -> ${wire.size} bytes)")
    }
    return 0
}

private fun cmdDecrypt(
    profile: String,
    blobHex: String,
    inFile: String,
    outFile: String,
): Int {
    val blob = fromHex(blobHex)
    val wire = File(inFile).readBytes()
    Pipeline.load(blob).use { pipe ->
        val plain = if (isStreamingProfile(profile)) {
            pipe.decryptStreamOneShot(wire)
        } else {
            pipe.decryptMessage(wire)
        }
        ensureParentDir(outFile)
        File(outFile).writeBytes(plain)
        println("decrypted $inFile -> $outFile (${wire.size} -> ${plain.size} bytes)")
    }
    return 0
}

private fun toHex(bytes: ByteArray): String =
    buildString(bytes.size * 2) {
        for (b in bytes) {
            append("0123456789abcdef"[(b.toInt() ushr 4) and 0xF])
            append("0123456789abcdef"[b.toInt() and 0xF])
        }
    }

/** Tolerant hex parse: whitespace stripped, optional 0x prefix,
 * case-insensitive. */
private fun fromHex(hex: String): ByteArray {
    val s = hex.filterNot { it.isWhitespace() }.removePrefix("0x").removePrefix("0X")
    require(s.length % 2 == 0) { "odd-length hex string" }
    return ByteArray(s.length / 2) { i ->
        val hi = Character.digit(s[2 * i], 16)
        val lo = Character.digit(s[2 * i + 1], 16)
        require(hi >= 0 && lo >= 0) { "non-hex character in blob hex" }
        ((hi shl 4) or lo).toByte()
    }
}
