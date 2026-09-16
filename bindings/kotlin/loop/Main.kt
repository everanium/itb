// Long-run stress harness. The loop utility holds one Pipeline handle
// per exercised cipher surface for minutes, hammers it with concurrent
// encrypt → decrypt → compare round-trips from N worker threads,
// rotates the outer masters and reopens the handle from its session
// blob on a schedule, and reports whether the process survived with
// every byte intact. It is the Kotlin binding's counterpart of the Go
// harness under tools/loop: the same flags, the same round structure,
// the same summary in both renderings.
//
// The default shape is full production: the Streaming AEAD profile
// with parallax on, wrapper on, hmac-blake3 MAC, Areion-SoEM-512 inner
// hash, 1024-bit keys, and the compile-in 512-bit nonce width, driven
// through a stream session by three workers for five minutes on 16 MiB
// plaintexts. Every worker owns a distinct CSPRNG-generated plaintext
// held for the whole run, so any cross-call state leakage inside the
// Pipeline surfaces as a data mismatch between workers rather than
// cancelling out.
//
// A failure is one of two things. A cipher, rekey or load call that
// returns a non-OK status is a worker error: the run stops, the
// summary lists it, the verdict is FAIL and the exit code 1. A
// round-trip that returns without error but with different bytes is a
// data mismatch: the process terminates on the spot with exit code 3,
// printing the worker, the iteration and the first differing offset,
// and no summary — the state that produced the wrong bytes is the
// evidence. A crash inside the shared library or the host runtime has
// no exit code of its own here; surfacing it is what the utility is
// for. Every call goes through the Kotlin binding's own wrapper types,
// which sit on the Java binding's JNI proxy, so a Go c-shared runtime
// and a HotSpot JVM share one process — the interaction the long run
// is meant to expose.
//
// Usage:
//
//   java -jar build/libs/loop.jar --duration 5m --goroutines 3 \
//          --shape stream --hash areion512 --mac hmac-blake3 \
//          --payload-size 16MB --memlimit auto --parallax on --wrapper on
//
// Ctrl-C triggers a graceful shutdown: in-flight iterations complete,
// then the partial summary prints.

package io.github.everanium.itb3.kotlin.loop

import io.github.everanium.itb3.kotlin.ItbRuntime
import io.github.everanium.itb3.kotlin.Opts
import io.github.everanium.itb3.kotlin.Pipeline
import io.github.everanium.itb3.kotlin.Profile
import java.util.concurrent.BrokenBarrierException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.locks.ReentrantLock
import java.util.concurrent.locks.ReentrantReadWriteLock

/** --goroutines ceiling; the harness targets modest hosts and each
 * worker pins payload-sized buffers for the whole run. */
const val MAX_WORKERS = 10

/** The concurrency mode this binding implements, as the summary
 * reports it (shared-handle / independent-handles / single). */
const val CONCURRENCY = "shared-handle"

/** Largest slice fed to a stream session per write; the drain after
 * every write uses the same bound. */
const val PUMP_SLICE = 1 shl 20

/** Profiles the shape-based pair is built against when --profile is
 * empty. */
private const val DEFAULT_STREAM_PROFILE = "streaming-aead-triple-mac-v1"
private const val DEFAULT_MESSAGE_PROFILE = "singlemsg-triple-mac-v1"

/** The keystream-capable primitive supplied for a layer a profile
 * leaves unnamed: PRF-grade, so sound outside the barrier, and the
 * closest relative of the AES-based inner primitive whose profiles
 * need the fill. */
private const val KEYSTREAM_FILL_CIPHER = "aescmac"

/** The parallax segment size a filled palette runs with — the
 * library's own default; a schedule rejects zero. */
private const val KEYSTREAM_FILL_SEGMENT = 4093L

/** Prints one prefixed status line to stdout. */
fun logLine(line: String) = println("[loop] $line")

fun onOff(b: Boolean): String = if (b) "on" else "off"

/** Renders an encoder policy env value for the summary: the raw string
 * when set, "default" when the shipped ladder applies. */
fun policyLabel(name: String): String {
    val v = System.getenv(name)
    return if (v.isNullOrBlank()) "default" else v.trimStart()
}

/** The resolved command line. */
class Config(
    val durationNs: Long,
    val iterations: Long,
    val workersRequested: Int,
    val workers: Int,
    val shape: Shape,
    val hash: String,
    val mac: String,
    val payload: Long,
    var memlimit: Long,
    val memlimitAuto: Boolean,
    val gogc: Int,
    val parallax: Boolean,
    val wrapper: Boolean,
    val profile: String,
    val keyBits: Long,
    val nonceBits: Long,
    val chunkSize: Long,
    val barrierFill: Long,
    val gomaxprocs: Int,
    val rekeyEvery: Long,
    val blobCycleEvery: Long,
    val payloadMode: PayloadMode,
    val seed: Long,
    val jsonOutput: Boolean,
    val memprofile: String,
)

/** The Pipeline handles and their retained blobs, behind the lock that
 * keeps iterations clear of handle mutation. */
class Pipes {
    var stream: Pipeline? = null
    var msg: Pipeline? = null

    /** The blob Init handed out, replaced by every rekey; the input of
     * the next blob reopen. */
    var streamBlob: ByteArray = ByteArray(0)
    var msgBlob: ByteArray = ByteArray(0)
}

/** One worker's counters, read by the summary after every worker has
 * returned, and the error it stopped on. */
class Counters {
    val iters = AtomicLong()
    val bytesEnc = AtomicLong()
    val bytesDec = AtomicLong()
    val nanosEnc = AtomicLong()
    val nanosDec = AtomicLong()
    private val errorLock = Any()
    private var error: String? = null

    fun addEncrypt(ns: Long) {
        nanosEnc.addAndGet(ns)
    }

    fun addDecrypt(ns: Long) {
        nanosDec.addAndGet(ns)
    }

    fun addIteration(encBytes: Long, decBytes: Long) {
        iters.incrementAndGet()
        bytesEnc.addAndGet(encBytes)
        bytesDec.addAndGet(decBytes)
    }

    /** Records the first error only. */
    fun setError(text: String) = synchronized(errorLock) {
        if (error == null) {
            error = text
        }
    }

    fun error(): String? = synchronized(errorLock) { error }
}

/** One worker's private state, owned by its thread: its plaintext, its
 * reusable pump accumulators, its generator. */
class WorkerState(
    val id: Int,
    val plaintext: ByteArray,
    val payloadMode: PayloadMode,
    val seeded: Boolean,
    val rng: Rng,
    val scratch: ByteArray,
) {
    val wire = Acc(1 shl 20)
    val plain = Acc(1 shl 20)
}

/** The state every worker shares. */
class RunState(
    val cfg: Config,
    val streamProfile: String,
    val msgProfile: String,
    val pipes: Pipes,
    val workers: Array<Counters>,
    val warmupDone: CyclicBarrier,
    val release: CyclicBarrier,
    var active: Int,
) {
    /** Handle mutation. Iterations hold the read side for their whole
     * encrypt → decrypt → compare; rekey and blob reopen take the write
     * side, so no cipher call is in flight while a handle's keying
     * changes or the handle itself is swapped, and no encrypt is
     * separated from its decrypt by either. */
    val pipesLock = ReentrantReadWriteLock()

    val rekeys = AtomicLong()
    val blobCycles = AtomicLong()

    /** Set by the duration deadline, by a signal, or by a failing
     * worker; checked by every worker before it starts an iteration. */
    @Volatile
    var stop = false

    val doneLock = ReentrantLock()
    val doneCond: java.util.concurrent.locks.Condition = doneLock.newCondition()
    var finishNanos = 0L

    var rssWarmup = 0L
    var rssPeak = 0L
    var rssFinal = 0L
    var poolWarmup: LongArray = LongArray(0)
    var poolSteady: LongArray = LongArray(0)
}

// ----------------------------------------------------------------------
// Flags
// ----------------------------------------------------------------------

/** The raw flag values before validation. */
private class RawFlags {
    var barrierFill = 0L
    var blobCycleEvery = 0L
    var chunkSize = "0"
    var duration = "5m"
    var gogc = 0L
    var gomaxprocs = 0L
    var goroutines = 3L
    var hash = "areion512"
    var iterations = 0L
    var jsonOutput = false
    var keyBits = 0L
    var mac = "hmac-blake3"
    var memlimit = "auto"
    var memprofile = ""
    var nonceBits = 0L
    var parallax = "on"
    var payloadMode = "fixed"
    var payloadSize = "16MB"
    var profile = ""
    var rekeyEvery = 0L
    var seed = 0L
    var shape = "stream"
    var wrapper = "on"
}

/** One command-line flag: its name, the type label the usage prints,
 * its help text, whether it takes a value, the default-value suffix
 * the usage appends, and the store that parses a value into the raw
 * flags. Values are validated after the whole line is parsed. The
 * table is in alphabetical order — the order the usage prints. */
private class Flag(
    val name: String,
    val typeLabel: String,
    val help: String,
    val isBool: Boolean,
    val defaultSuffix: String,
    val store: (RawFlags, String) -> Boolean,
)

private fun defaultOf(v: Long): String = if (v != 0L) " (default $v)" else ""

private fun defaultOf(v: String): String = if (v.isEmpty()) "" else " (default \"$v\")"

private val FLAGS: List<Flag> = buildFlags()

private fun buildFlags(): List<Flag> {
    val d = RawFlags()
    return listOf(
        Flag(
            "barrier-fill", "int",
            "DRBG barrier fill margin: 1 | 2 | 4 | 8 | 16 | 32; 0 = profile default (1)",
            false, defaultOf(d.barrierFill),
        ) { f, s -> s.toLongOrNull()?.also { f.barrierFill = it } != null },
        Flag(
            "blob-cycle-every", "int",
            "reopen each pipeline from its session blob every N iterations per worker; 0 = never",
            false, "",
        ) { f, s -> s.toLongOrNull()?.also { f.blobCycleEvery = it } != null },
        Flag(
            "chunk-size", "string",
            "streaming chunk-size budget (e.g. 4MB); 0 = profile default; " +
                "inert for pure message shape",
            false, defaultOf(d.chunkSize),
        ) { f, s -> f.chunkSize = s; true },
        Flag(
            "duration", "duration",
            "run duration (Go format: 30s / 5m / 1h); ignored when --iterations > 0",
            false, defaultOf(d.duration),
        ) { f, s -> f.duration = s; true },
        Flag(
            "gogc", "int",
            "GC trigger percentage; 0 = leave the runtime default",
            false, defaultOf(d.gogc),
        ) { f, s -> s.toLongOrNull()?.also { f.gogc = it } != null },
        Flag(
            "gomaxprocs", "int",
            "Go runtime GOMAXPROCS override; 0 = inherit from the environment",
            false, defaultOf(d.gomaxprocs),
        ) { f, s -> s.toLongOrNull()?.also { f.gomaxprocs = it } != null },
        Flag(
            "goroutines", "int",
            "concurrent workers (1..10); on runtimes without parallelism values above 1 " +
                "are clamped to 1",
            false, defaultOf(d.goroutines),
        ) { f, s -> s.toLongOrNull()?.also { f.goroutines = it } != null },
        Flag(
            "hash", "string",
            "inner ITB hash primitive name",
            false, defaultOf(d.hash),
        ) { f, s -> f.hash = s; true },
        Flag(
            "iterations", "int",
            "fixed per-worker iteration count; 0 = duration-based",
            false, "",
        ) { f, s -> s.toLongOrNull()?.also { f.iterations = it } != null },
        Flag(
            "json-output", "",
            "print the final summary as one compact JSON object instead of log lines",
            true, "",
        ) { f, s ->
            when (s) {
                "true" -> { f.jsonOutput = true; true }
                "false" -> { f.jsonOutput = false; true }
                else -> false
            }
        },
        Flag(
            "key-bits", "int",
            "per-seed key width in bits: 512 | 1024 | 2048; 0 = profile default (1024)",
            false, defaultOf(d.keyBits),
        ) { f, s -> s.toLongOrNull()?.also { f.keyBits = it } != null },
        Flag(
            "mac", "string",
            "MAC primitive name",
            false, defaultOf(d.mac),
        ) { f, s -> f.mac = s; true },
        Flag(
            "memlimit", "string",
            "Go heap soft limit: auto (1GiB when goroutines <= 3, else 256MiB, applied only " +
                "when the runtime has no limit) or a size (e.g. 512MB)",
            false, defaultOf(d.memlimit),
        ) { f, s -> f.memlimit = s; true },
        Flag(
            "memprofile", "string",
            "write a Go runtime heap profile (pprof) to this path at the end of the run; " +
                "empty = none",
            false, defaultOf(d.memprofile),
        ) { f, s -> f.memprofile = s; true },
        Flag(
            "nonce-bits", "int",
            "on-wire nonce width in bits: 128 | 256 | 512; 0 = profile default (512)",
            false, defaultOf(d.nonceBits),
        ) { f, s -> s.toLongOrNull()?.also { f.nonceBits = it } != null },
        Flag(
            "parallax", "string",
            "parallax layer: on | off",
            false, defaultOf(d.parallax),
        ) { f, s -> f.parallax = s; true },
        Flag(
            "payload-mode", "string",
            "plaintext content: fixed | rotating | pattern-zero | pattern-ff | pattern-ascii",
            false, defaultOf(d.payloadMode),
        ) { f, s -> f.payloadMode = s; true },
        Flag(
            "payload-size", "string",
            "per-iteration plaintext size (e.g. 1MB / 16MB / 64MB)",
            false, defaultOf(d.payloadSize),
        ) { f, s -> f.payloadSize = s; true },
        Flag(
            "profile", "string",
            "exercise this single registered triple profile (overrides --shape with the " +
                "profile's surface); empty = shape-based profile pair",
            false, defaultOf(d.profile),
        ) { f, s -> f.profile = s; true },
        Flag(
            "rekey-every", "int",
            "rotate the parallax + wrapper masters via Rekey every N iterations per worker; " +
                "0 = never",
            false, "",
        ) { f, s -> s.toLongOrNull()?.also { f.rekeyEvery = it } != null },
        Flag(
            "seed", "uint",
            "deterministic plaintext RNG seed for bug reproduction, NOT for security testing " +
                "(pipeline keys stay CSPRNG-drawn); 0 = crypto/rand plaintexts",
            false, "",
        ) { f, s ->
            try {
                f.seed = java.lang.Long.parseUnsignedLong(s)
                true
            } catch (e: NumberFormatException) {
                false
            }
        },
        Flag(
            "shape", "string",
            "cipher surface to exercise: stream | message | stream_one_shot | both",
            false, defaultOf(d.shape),
        ) { f, s -> f.shape = s; true },
        Flag(
            "wrapper", "string",
            "wrapper (Outer cipher) layer: on | off",
            false, defaultOf(d.wrapper),
        ) { f, s -> f.wrapper = s; true },
    )
}

private fun usage() {
    System.err.println("Usage of loop:")
    for (fl in FLAGS) {
        System.err.println(
            if (fl.typeLabel.isEmpty()) "  -${fl.name}" else "  -${fl.name} ${fl.typeLabel}",
        )
        System.err.println("    \t" + fl.help + fl.defaultSuffix)
    }
}

/** Parses argv into the raw flag values. Accepts -name value, --name
 * value, -name=value and --name=value; a boolean flag takes no value
 * unless given as -name=true / -name=false. True for -h / --help
 * (usage printed); null after printing the error. */
private fun parseArgv(args: Array<String>, f: RawFlags): Boolean? {
    var i = 0
    while (i < args.size) {
        val arg = args[i]
        if (arg.length <= 1 || arg[0] != '-') {
            System.err.println("loop: unexpected positional arguments: [$arg]")
            return null
        }
        var name = if (arg.startsWith("--")) arg.substring(2) else arg.substring(1)
        if (name == "h" || name == "help") {
            usage()
            return true
        }
        var inline: String? = null
        val eq = name.indexOf('=')
        if (eq >= 0) {
            inline = name.substring(eq + 1)
            name = name.substring(0, eq)
        }
        val fl = FLAGS.firstOrNull { it.name == name }
        if (fl == null) {
            System.err.println("loop: flag provided but not defined: -$name")
            usage()
            return null
        }
        val value: String
        if (inline != null) {
            value = inline
        } else if (fl.isBool) {
            value = "true"
        } else {
            i++
            if (i >= args.size) {
                System.err.println("loop: flag needs an argument: -${fl.name}")
                return null
            }
            value = args[i]
        }
        if (!fl.store(f, value)) {
            System.err.println("loop: invalid value \"$value\" for flag -${fl.name}")
            return null
        }
        i++
    }
    return false
}

/** Whether name is in the shipped hash registry the binding
 * returns. */
private fun hashRegistered(name: String): Boolean = try {
    Pipeline.hashNames().contains(name)
} catch (e: Exception) {
    false
}

/** Resolves a registered profile to the shape family its record's mode
 * exposes by reading the record through the binding's lookup: a mode
 * beginning with "streaming" exposes the stream surfaces, one
 * beginning with "singlemsg" the message surface, "blob-only" none.
 * Prints the validation message and returns null on rejection. */
private fun profileSurface(name: String): Shape? {
    val p: Profile = try {
        Pipeline.lookup(name)
    } catch (e: Exception) {
        System.err.println("loop: --profile \"$name\" is not a registered triple profile")
        return null
    }
    if (p.mode().startsWith("streaming")) {
        return Shape.Stream
    }
    if (p.mode().startsWith("singlemsg")) {
        return Shape.Message
    }
    System.err.println("loop: --profile \"$name\" carries no cipher surface (blob-only mode)")
    return null
}

/** Applies a --profile's surface to the requested shape: a
 * message-surface profile forces message; a stream-surface profile
 * keeps stream or stream_one_shot as requested and turns message or
 * both into stream. */
private fun narrowShape(requested: Shape, surface: Shape): Shape = when {
    surface == Shape.Message -> Shape.Message
    requested == Shape.StreamOneShot -> Shape.StreamOneShot
    else -> Shape.Stream
}

/** The outcome of flag resolution: a config, or an exit code with the
 * message already printed. */
private class Parsed(val cfg: Config?, val code: Int)

/** Builds the resolved config from argv. Returns a null config with
 * code 0 for help and with code 2 after printing "loop: <message>" for
 * the first failing rule. */
private fun parseFlags(args: Array<String>): Parsed {
    val f = RawFlags()
    val help = parseArgv(args, f) ?: return Parsed(null, 2)
    if (help) {
        return Parsed(null, 0)
    }
    val durationNs = parseDuration(f.duration)
    if (durationNs == null || durationNs <= 0) {
        System.err.println("loop: --duration must be positive, got ${f.duration}")
        return Parsed(null, 2)
    }
    if (f.iterations < 0) {
        System.err.println("loop: --iterations must be >= 0, got ${f.iterations}")
        return Parsed(null, 2)
    }
    if (f.goroutines < 1 || f.goroutines > MAX_WORKERS) {
        System.err.println("loop: --goroutines must be in 1..$MAX_WORKERS, got ${f.goroutines}")
        return Parsed(null, 2)
    }
    // Concurrency mode. This binding runs shared-handle: JVM platform
    // threads call into one Pipeline handle concurrently. The Kotlin
    // Pipeline is a thin lifetime wrapper holding one Java Pipeline,
    // which is itself a long over an opaque Go-side registry key; every
    // entry it is passed to is re-entrant after construction, and the
    // one piece of mutable machinery behind it — the Java layer's
    // pooled direct scratch pair — is taken with an atomic swap so a
    // concurrent caller falls back to fresh buffers instead of sharing.
    // So --goroutines is the thread count verbatim, never clamped.
    val workers = f.goroutines.toInt()
    var shape = Shape.parse(f.shape)
    if (shape == null) {
        System.err.println(
            "loop: --shape must be stream | message | stream_one_shot | both, " +
                "got \"${f.shape}\"",
        )
        return Parsed(null, 2)
    }
    if (!hashRegistered(f.hash)) {
        System.err.println("loop: --hash \"${f.hash}\" is not a registered hash primitive")
        return Parsed(null, 2)
    }
    // --mac is validated by Init: the C ABI enumerates no MAC names.
    val payload = parseSize(f.payloadSize)
    if (payload == null) {
        System.err.println("loop: --payload-size: invalid size \"${f.payloadSize}\"")
        return Parsed(null, 2)
    }
    if (payload < 1) {
        System.err.println("loop: --payload-size must be at least 1 byte")
        return Parsed(null, 2)
    }
    val memlimitAuto = f.memlimit == "auto"
    val memlimit: Long
    if (memlimitAuto) {
        memlimit = if (workers <= 3) 1L shl 30 else 256L shl 20
    } else {
        val parsed = parseSize(f.memlimit)
        if (parsed == null) {
            System.err.println("loop: --memlimit: invalid size \"${f.memlimit}\"")
            return Parsed(null, 2)
        }
        memlimit = parsed
    }
    if (f.gogc < 0) {
        System.err.println("loop: --gogc must be >= 0, got ${f.gogc}")
        return Parsed(null, 2)
    }
    val parallax = when (f.parallax) {
        "on" -> true
        "off" -> false
        else -> {
            System.err.println("loop: --parallax must be on | off, got \"${f.parallax}\"")
            return Parsed(null, 2)
        }
    }
    val wrapper = when (f.wrapper) {
        "on" -> true
        "off" -> false
        else -> {
            System.err.println("loop: --wrapper must be on | off, got \"${f.wrapper}\"")
            return Parsed(null, 2)
        }
    }
    if (f.profile.isNotEmpty()) {
        val surface = profileSurface(f.profile) ?: return Parsed(null, 2)
        shape = narrowShape(shape, surface)
    }
    if (f.keyBits !in listOf(0L, 512L, 1024L, 2048L)) {
        System.err.println(
            "loop: --key-bits must be 512 | 1024 | 2048 (or 0 = profile default), " +
                "got ${f.keyBits}",
        )
        return Parsed(null, 2)
    }
    if (f.nonceBits !in listOf(0L, 128L, 256L, 512L)) {
        System.err.println(
            "loop: --nonce-bits must be 128 | 256 | 512 (or 0 = profile default), " +
                "got ${f.nonceBits}",
        )
        return Parsed(null, 2)
    }
    if (f.barrierFill !in listOf(0L, 1L, 2L, 4L, 8L, 16L, 32L)) {
        System.err.println(
            "loop: --barrier-fill must be 1 | 2 | 4 | 8 | 16 | 32 (or 0 = profile default), " +
                "got ${f.barrierFill}",
        )
        return Parsed(null, 2)
    }
    val chunkSize = parseSize(f.chunkSize)
    if (chunkSize == null) {
        System.err.println("loop: --chunk-size: invalid size \"${f.chunkSize}\"")
        return Parsed(null, 2)
    }
    if (f.gomaxprocs < 0) {
        System.err.println("loop: --gomaxprocs must be > 0 when specified, got ${f.gomaxprocs}")
        return Parsed(null, 2)
    }
    if (f.rekeyEvery < 0) {
        System.err.println("loop: --rekey-every must be >= 0, got ${f.rekeyEvery}")
        return Parsed(null, 2)
    }
    if (f.blobCycleEvery < 0) {
        System.err.println("loop: --blob-cycle-every must be >= 0, got ${f.blobCycleEvery}")
        return Parsed(null, 2)
    }
    val payloadMode = PayloadMode.parse(f.payloadMode)
    if (payloadMode == null) {
        System.err.println(
            "loop: --payload-mode must be fixed | rotating | pattern-zero | pattern-ff | " +
                "pattern-ascii, got \"${f.payloadMode}\"",
        )
        return Parsed(null, 2)
    }
    return Parsed(
        Config(
            durationNs = durationNs,
            iterations = f.iterations,
            workersRequested = workers,
            workers = workers,
            shape = shape,
            hash = f.hash,
            mac = f.mac,
            payload = payload,
            memlimit = memlimit,
            memlimitAuto = memlimitAuto,
            gogc = f.gogc.toInt(),
            parallax = parallax,
            wrapper = wrapper,
            profile = f.profile,
            keyBits = f.keyBits,
            nonceBits = f.nonceBits,
            chunkSize = chunkSize,
            barrierFill = f.barrierFill,
            gomaxprocs = f.gomaxprocs.toInt(),
            rekeyEvery = f.rekeyEvery,
            blobCycleEvery = f.blobCycleEvery,
            payloadMode = payloadMode,
            seed = f.seed,
            jsonOutput = f.jsonOutput,
            memprofile = f.memprofile,
        ),
        0,
    )
}

// ----------------------------------------------------------------------
// Signals
// ----------------------------------------------------------------------

@Volatile
private var signalSeen = false

/** Counted down once the summary has been emitted, so the shutdown
 * hook can hold the JVM's own termination back until then. */
private val SUMMARY_DONE = CountDownLatch(1)

/**
 * Graceful stop. SIGINT / SIGTERM set a flag the main thread polls
 * while it waits for the workers; it turns the flag into the stop
 * request every worker checks before starting an iteration, so a
 * signal interrupts nothing mid-call — the in-flight encrypt / decrypt
 * / compare completes, the worker returns, and the partial summary
 * prints with the verdict the completed iterations earned.
 * Kotlin-specific: the supported way to observe a termination signal
 * on this runtime is a shutdown hook, which runs concurrently with the
 * main thread rather than in place of it and cannot set the exit code,
 * so the hook only raises the flag and then blocks until the summary
 * is out; the verdict's code is then delivered by halting the runtime
 * from the main thread, which is also what makes the exit code the
 * verdict's rather than the JVM's own signal code.
 */
private fun installSignals() {
    val hook = Thread(
        {
            signalSeen = true
            try {
                SUMMARY_DONE.await(2, TimeUnit.MINUTES)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
            }
        },
        "loop-signal",
    )
    java.lang.Runtime.getRuntime().addShutdownHook(hook)
}

// ----------------------------------------------------------------------
// Pipelines
// ----------------------------------------------------------------------

/** Opts plus whether a keystream layer was filled into them. */
private class Filled(val opts: Opts, val filled: Boolean)

/**
 * Supplies the keystream-capable primitive for every layer the profile
 * record leaves unnamed and the run engages: a missing parallax
 * palette becomes three copies of the fill cipher (with the library's
 * default segment size when the record carries none), a missing outer
 * cipher becomes the fill cipher. These are opts overrides that fold
 * into the resolved record the blob carries — a derived profile is
 * never registered, so no name the receiver did not agree to reaches
 * the wire. Null after printing the validation message.
 */
private fun fillKeystreamLayers(
    name: String,
    opts: Opts,
    wantParallax: Boolean,
    wantWrapper: Boolean,
): Filled? {
    val p: Profile = try {
        Pipeline.lookup(name)
    } catch (e: Exception) {
        System.err.println("loop: --profile \"$name\" is not a registered triple profile")
        return null
    }
    var filled = false
    if (wantParallax && p.palette().isEmpty()) {
        opts.parallaxPalette(
            KEYSTREAM_FILL_CIPHER,
            KEYSTREAM_FILL_CIPHER,
            KEYSTREAM_FILL_CIPHER,
        )
        if (p.segment() == 0) {
            // A recipe that never carried a palette never carried a
            // segment size either, and the schedule rejects zero.
            opts.parallaxSegmentSize(KEYSTREAM_FILL_SEGMENT)
        }
        filled = true
    }
    if (wantWrapper && p.outer().isEmpty()) {
        opts.outerCipher(KEYSTREAM_FILL_CIPHER)
        filled = true
    }
    return Filled(opts, filled)
}

/** A constructed Pipeline and the blob it handed out. */
private class Built(val pipe: Pipeline, val blob: ByteArray)

/**
 * Constructs one Pipeline against profile with every flag-carried
 * override in the opts string (zero values included — the shared
 * library treats zero as "profile default"), then obtains the Init
 * blob once through save: the binding's init entry does not hand the
 * blob back, and the bytes are the ones Init produced. Later blob
 * reopens use the retained blob; save is never called again.
 */
private fun buildPipeline(cfg: Config, profile: String): Built? {
    var opts = Opts()
        .innerHash(cfg.hash)
        .macName(cfg.mac)
        .parallax(cfg.parallax)
        .wrapper(cfg.wrapper)
        .keyBits(cfg.keyBits)
        .nonceBits(cfg.nonceBits)
        .barrierFill(cfg.barrierFill)
        .chunkSize(cfg.chunkSize)
    if (cfg.profile.isNotEmpty()) {
        val filled = fillKeystreamLayers(cfg.profile, opts, cfg.parallax, cfg.wrapper)
            ?: return null
        opts = filled.opts
        if (filled.filled) {
            System.err.println(
                "loop: ${cfg.profile} leaves the requested keystream layers unnamed; " +
                    "$KEYSTREAM_FILL_CIPHER supplied for them",
            )
        }
    }
    val pipe = try {
        Pipeline.init(profile, opts)
    } catch (e: Exception) {
        System.err.println("loop: Init($profile): ${detail(e)}")
        return null
    }
    val blob = try {
        pipe.save()
    } catch (e: Exception) {
        System.err.println("loop: Save($profile): ${detail(e)}")
        pipe.close()
        return null
    }
    logPipelineInitialised(profile, blob)
    return Built(pipe, blob)
}

private fun dash(s: String): String = if (s.isEmpty()) "-" else s

/** Prints the construction line with the recipe read back from the
 * blob the Pipeline handed out, not echoed from the flags: every
 * construction override is proven to have reached the library by the
 * value the receiver would see. Record values that are empty (a No MAC
 * profile's MAC, a mixed profile's single hash) print as "-". */
private fun logPipelineInitialised(profile: String, blob: ByteArray) {
    val rec: Profile = try {
        Pipeline.inspect(blob)
    } catch (e: Exception) {
        logLine(
            "pipeline initialised: profile=$profile blob=${blob.size} bytes " +
                "(inspect: ${detail(e)})",
        )
        return
    }
    logLine(
        "pipeline initialised: profile=$profile blob=${blob.size} bytes" +
            " hash=${dash(rec.hash())}" +
            " key-bits=${rec.keyBits()}" +
            " nonce-bits=${rec.nonceBits() ?: 0}" +
            " barrier-fill=${rec.barrierFill() ?: 0}" +
            " chunk-size=${rec.chunk()}" +
            " mac=${dash(rec.mac())}" +
            " parallax=${onOff(rec.parallax())}" +
            " wrapper=${onOff(rec.wrapper())}",
    )
}

// ----------------------------------------------------------------------
// Run
// ----------------------------------------------------------------------

private fun run(args: Array<String>): Int {
    val parsed = parseFlags(args)
    val cfg = parsed.cfg ?: return parsed.code

    // Runtime shaping. A long run under allocation churn grows the Go
    // heap inside the shared library without bound unless a soft limit
    // paces the collector, so a limit is always in force: an explicit
    // --memlimit is set as given, and auto caps the heap only when the
    // runtime reports no limit at all (a limit already installed from
    // the environment is left standing). The GC percentage and
    // GOMAXPROCS are set only when their flag is non-zero — a zero flag
    // skips the setter rather than calling it with zero, because zero
    // is a real value to the GC-percent setter, and a call would
    // clobber whatever the environment installed. All of it lands
    // before any Pipeline exists so the baselines are taken under the
    // shaped runtime.
    if (cfg.memlimitAuto) {
        if (ItbRuntime.setMemoryLimit(-1) == Long.MAX_VALUE) {
            ItbRuntime.setMemoryLimit(cfg.memlimit)
        }
    } else {
        ItbRuntime.setMemoryLimit(cfg.memlimit)
    }
    cfg.memlimit = ItbRuntime.setMemoryLimit(-1)
    if (cfg.gogc > 0) {
        ItbRuntime.setGCPercent(cfg.gogc)
    }
    if (cfg.gomaxprocs > 0) {
        ItbRuntime.setGOMAXPROCS(cfg.gomaxprocs)
    }

    logLine(
        "start: duration=${humanDuration(cfg.durationNs)}" +
            " iterations=${cfg.iterations}" +
            " goroutines=${cfg.workersRequested}" +
            " workers=${cfg.workers}" +
            " concurrency=$CONCURRENCY" +
            " shape=${cfg.shape.label}" +
            " hash=${cfg.hash}" +
            " mac=${cfg.mac}" +
            " payload=${humanBytes(cfg.payload)}" +
            " memlimit=${humanBytes(cfg.memlimit)}" +
            " parallax=${onOff(cfg.parallax)}" +
            " wrapper=${onOff(cfg.wrapper)}",
    )
    logLine(
        "overrides: profile=\"${cfg.profile}\"" +
            " key-bits=${cfg.keyBits}" +
            " nonce-bits=${cfg.nonceBits}" +
            " chunk-size=${humanBytes(cfg.chunkSize)}" +
            " barrier-fill=${cfg.barrierFill}" +
            " gomaxprocs=${cfg.gomaxprocs}" +
            " rekey-every=${cfg.rekeyEvery}" +
            " blob-cycle-every=${cfg.blobCycleEvery}" +
            " payload-mode=${cfg.payloadMode.label}" +
            " seed=${java.lang.Long.toUnsignedString(cfg.seed)}" +
            " json-output=${if (cfg.jsonOutput) "true" else "false"}",
    )
    logLine(
        "policy: microbatch-tiers=${policyLabel("ITB_MICROBATCH_TIERS")}" +
            " hashpool-starters=${policyLabel("ITB_HASHPOOL_STARTERS")}",
    )

    // Pipeline construction — one shared handle per exercised shape.
    // stream and stream_one_shot share the streaming handle.
    val streamProfile = if (cfg.profile.isEmpty()) DEFAULT_STREAM_PROFILE else cfg.profile
    val msgProfile = if (cfg.profile.isEmpty()) DEFAULT_MESSAGE_PROFILE else cfg.profile
    val pipes = Pipes()
    if (cfg.shape == Shape.Stream || cfg.shape == Shape.StreamOneShot || cfg.shape == Shape.Both) {
        val built = buildPipeline(cfg, streamProfile) ?: return 1
        pipes.stream = built.pipe
        pipes.streamBlob = built.blob
    }
    if (cfg.shape == Shape.Message || cfg.shape == Shape.Both) {
        val built = buildPipeline(cfg, msgProfile) ?: return 1
        pipes.msg = built.pipe
        pipes.msgBlob = built.blob
    }

    // Allocation posture. Per-worker plaintexts are allocated once and
    // held for the whole run (rotating mode refills them in place per
    // iteration); the pump accumulators and the drain scratch live
    // inside each worker and are reused across iterations; the message
    // and one-shot outputs are allocated by the binding per call and
    // reclaimed per iteration. Under the default fixed CSPRNG mode
    // every worker's buffer is distinct, so cross-worker data crossover
    // is detectable; pattern modes trade that property for content
    // edge-case coverage.
    if (cfg.payload > Int.MAX_VALUE - 8) {
        System.err.println("loop: --payload-size exceeds the largest JVM array")
        return 1
    }
    val states = ArrayList<WorkerState>(cfg.workers)
    for (id in 0 until cfg.workers) {
        val w = WorkerState(
            id = id,
            plaintext = ByteArray(cfg.payload.toInt()),
            payloadMode = cfg.payloadMode,
            seeded = cfg.seed != 0L,
            rng = Rng(seedWorker(cfg.seed, id)),
            scratch = ByteArray(PUMP_SLICE),
        )
        if (!fillPayload(cfg.payloadMode, w.seeded, w.rng, w.plaintext)) {
            System.err.println("loop: payload fill: csprng")
            return 1
        }
        states.add(w)
    }

    installSignals()
    val r = RunState(
        cfg = cfg,
        streamProfile = streamProfile,
        msgProfile = msgProfile,
        pipes = pipes,
        workers = Array(cfg.workers) { Counters() },
        warmupDone = CyclicBarrier(cfg.workers + 1),
        release = CyclicBarrier(cfg.workers + 1),
        active = cfg.workers,
    )

    // Warmup barrier. Every worker runs one iteration and waits; the
    // clock starts only once all of them have paid their first-call
    // costs (pool warm-up, lazy kernel dispatch, page faults on the
    // payload buffers, and on this runtime the tiered JIT's first pass
    // over the iteration body), and the RSS and pool baselines taken
    // here describe a process that has already run the whole cipher
    // path once per worker.
    val warmupStart = System.nanoTime()
    val threads = states.map { w ->
        Thread({ runWorker(r, w) }, "loop-worker-${w.id}").also {
            it.isDaemon = false
            it.start()
        }
    }
    try {
        r.warmupDone.await()
    } catch (e: InterruptedException) {
        Thread.currentThread().interrupt()
        System.err.println("loop: warmup barrier: $e")
        return 1
    } catch (e: BrokenBarrierException) {
        System.err.println("loop: warmup barrier: $e")
        return 1
    }
    val (rssWarmup, _) = readRss()
    val poolWarmup = poolSnapshot()
    logLine(
        "warmup: ${cfg.workers} workers x 1 iter completed in " +
            humanDuration(roundTo(System.nanoTime() - warmupStart, 100_000_000L)) +
            " (baseline rss=${humanBytes(rssWarmup)})",
    )

    // Open the gate; the duration is a deadline the waiter below
    // enforces in duration mode.
    val start = System.nanoTime()
    try {
        r.release.await()
    } catch (e: InterruptedException) {
        Thread.currentThread().interrupt()
        System.err.println("loop: release barrier: $e")
        return 1
    } catch (e: BrokenBarrierException) {
        System.err.println("loop: release barrier: $e")
        return 1
    }

    // Wait for every worker, polling every 100 ms so the deadline and a
    // signal are both noticed promptly.
    var finish = start
    r.doneLock.lock()
    try {
        while (r.active > 0) {
            if (signalSeen || (cfg.iterations == 0L && System.nanoTime() - start >= cfg.durationNs)) {
                r.stop = true
            }
            try {
                r.doneCond.await(100, TimeUnit.MILLISECONDS)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                r.stop = true
            }
        }
        if (r.finishNanos != 0L) {
            finish = r.finishNanos
        }
    } finally {
        r.doneLock.unlock()
    }
    val elapsedNs = finish - start
    val (rssFinal, rssPeak) = readRss()
    val poolSteady = poolSnapshot()
    for (t in threads) {
        try {
            t.join()
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }
    r.rssWarmup = rssWarmup
    r.rssFinal = rssFinal
    r.rssPeak = rssPeak
    r.poolWarmup = poolWarmup
    r.poolSteady = poolSteady

    if (cfg.memprofile.isNotEmpty()) {
        try {
            ItbRuntime.writeHeapProfile(cfg.memprofile)
            logLine("memprofile: heap profile written to ${cfg.memprofile}")
        } catch (e: Exception) {
            System.err.println("loop: memprofile: ${detail(e)}")
        }
    }

    val exit = emitSummary(r, elapsedNs)
    r.pipes.stream?.close()
    r.pipes.msg?.close()
    return exit
}

/** Entry point. */
fun main(args: Array<String>) {
    val code = run(args)
    System.out.flush()
    System.err.flush()
    SUMMARY_DONE.countDown()
    // Kotlin-specific. The verdict's code is delivered by halting the
    // runtime rather than by returning from main: when a signal has
    // started the shutdown sequence, returning would let the JVM finish
    // that sequence with its own signal-derived code instead of this
    // one.
    java.lang.Runtime.getRuntime().halt(code)
}
