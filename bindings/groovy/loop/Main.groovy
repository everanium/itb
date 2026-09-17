// Long-run stress harness. The loop utility holds one Pipeline handle
// per exercised cipher surface for minutes, hammers it with concurrent
// encrypt → decrypt → compare round-trips from N worker threads,
// rotates the outer masters and reopens the handle from its session
// blob on a schedule, and reports whether the process survived with
// every byte intact. It is the Groovy binding's counterpart of the Go
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
// for. Every call goes through the Groovy binding's own wrapper
// classes, which sit on the Java binding's JNI proxy, so a Go c-shared
// runtime and a HotSpot JVM share one process — the interaction the
// long run is meant to expose.
//
// Usage:
//
//   java -jar build/libs/loop.jar --duration 5m --goroutines 3 \
//          --shape stream --hash areion512 --mac hmac-blake3 \
//          --payload-size 16MB --memlimit auto --parallax on --wrapper on
//
// Ctrl-C triggers a graceful shutdown: in-flight iterations complete,
// then the partial summary prints.

package io.github.everanium.itb3.groovy.loop

import groovy.transform.CompileStatic

import java.util.concurrent.BrokenBarrierException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.locks.Condition
import java.util.concurrent.locks.ReentrantLock
import java.util.concurrent.locks.ReentrantReadWriteLock

import io.github.everanium.itb3.groovy.Opts
import io.github.everanium.itb3.groovy.Pipeline
import io.github.everanium.itb3.groovy.Runtime as ItbRuntime
import io.github.everanium.itb3.Profile

/** The resolved command line. */
@CompileStatic
final class Config {
    long durationNs
    long iterations
    int workersRequested
    int workers
    Shape shape
    String hash = ''
    String mac = ''
    long payload
    long memlimit
    boolean memlimitAuto
    int gogc
    boolean parallax
    boolean wrapper
    String profile = ''
    long keyBits
    long nonceBits
    long chunkSize
    long barrierFill
    int gomaxprocs
    long rekeyEvery
    long blobCycleEvery
    PayloadMode payloadMode
    long seed
    boolean jsonOutput
    String memprofile = ''
}

/** The Pipeline handles and their retained blobs, behind the lock that
 * keeps iterations clear of handle mutation. */
@CompileStatic
final class Pipes {
    Pipeline stream
    Pipeline msg

    /** The blob Init handed out, replaced by every rekey; the input of
     * the next blob reopen. */
    byte[] streamBlob = new byte[0]
    byte[] msgBlob = new byte[0]
}

/** One worker's counters, read by the summary after every worker has
 * returned, and the error it stopped on. */
@CompileStatic
final class Counters {
    final AtomicLong iters = new AtomicLong()
    final AtomicLong bytesEnc = new AtomicLong()
    final AtomicLong bytesDec = new AtomicLong()
    final AtomicLong nanosEnc = new AtomicLong()
    final AtomicLong nanosDec = new AtomicLong()
    private final Object errorLock = new Object()
    private String error

    void addEncrypt(long ns) {
        nanosEnc.addAndGet(ns)
    }

    void addDecrypt(long ns) {
        nanosDec.addAndGet(ns)
    }

    void addIteration(long encBytes, long decBytes) {
        iters.incrementAndGet()
        bytesEnc.addAndGet(encBytes)
        bytesDec.addAndGet(decBytes)
    }

    /** Records the first error only. */
    void setError(String text) {
        synchronized (errorLock) {
            if (error == null) {
                error = text
            }
        }
    }

    String error() {
        synchronized (errorLock) {
            return error
        }
    }
}

/** One worker's private state, owned by its thread: its plaintext, its
 * reusable pump accumulators, its generator. */
@CompileStatic
final class WorkerState {
    int id
    byte[] plaintext = new byte[0]
    PayloadMode payloadMode
    boolean seeded
    Rng rng
    final Acc wire = new Acc(1 << 20)
    final Acc plain = new Acc(1 << 20)
    byte[] scratch = new byte[0]
}

/** The state every worker shares. */
@CompileStatic
final class RunState {
    Config cfg = new Config()
    String streamProfile = ''
    String msgProfile = ''

    /** Handle mutation. Iterations hold the read side for their whole
     * encrypt → decrypt → compare; rekey and blob reopen take the
     * write side, so no cipher call is in flight while a handle's
     * keying changes or the handle itself is swapped, and no encrypt
     * is separated from its decrypt by either. */
    final ReentrantReadWriteLock pipesLock = new ReentrantReadWriteLock()

    Pipes pipes = new Pipes()
    final AtomicLong rekeys = new AtomicLong()
    final AtomicLong blobCycles = new AtomicLong()
    Counters[] workers = new Counters[0]

    /** Warmup barrier: workers arrive at warmupDone after iteration 0
     * and at release once main has taken the baselines. */
    CyclicBarrier warmupDone = new CyclicBarrier(1)
    CyclicBarrier release = new CyclicBarrier(1)

    /** Set by the duration deadline, by a signal, or by a failing
     * worker; checked by every worker before it starts an
     * iteration. */
    volatile boolean stop

    final ReentrantLock doneLock = new ReentrantLock()
    final Condition doneCond = doneLock.newCondition()
    int active
    long finishNanos

    long rssWarmup
    long rssPeak
    long rssFinal
    long[] poolWarmup = new long[0]
    long[] poolSteady = new long[0]
}

/** The raw flag values before validation. */
@CompileStatic
final class RawFlags {
    long barrierFill
    long blobCycleEvery
    String chunkSize = '0'
    String duration = '5m'
    long gogc
    long gomaxprocs
    long goroutines = 3L
    String hash = 'areion512'
    long iterations
    boolean jsonOutput
    long keyBits
    String mac = 'hmac-blake3'
    String memlimit = 'auto'
    String memprofile = ''
    long nonceBits
    String parallax = 'on'
    String payloadMode = 'fixed'
    String payloadSize = '16MB'
    String profile = ''
    long rekeyEvery
    long seed
    String shape = 'stream'
    String wrapper = 'on'
}

/** One command-line flag: its name, the type label the usage prints,
 * its help text, whether it takes a value, the default-value suffix
 * the usage appends, and the store that parses a value into the raw
 * flags. Values are validated after the whole line is parsed. The
 * table is in alphabetical order — the order the usage prints. */
@CompileStatic
final class Flag {
    final String name
    final String typeLabel
    final String help
    final boolean isBool
    final String defaultSuffix
    final Closure<Boolean> store

    Flag(String name, String typeLabel, String help, boolean isBool,
            String defaultSuffix, Closure<Boolean> store) {
        this.name = name
        this.typeLabel = typeLabel
        this.help = help
        this.isBool = isBool
        this.defaultSuffix = defaultSuffix
        this.store = store
    }
}

/** Opts plus whether a keystream layer was filled into them. */
@CompileStatic
final class Filled {
    final Opts opts
    final boolean filled

    Filled(Opts opts, boolean filled) {
        this.opts = opts
        this.filled = filled
    }
}

/** A constructed Pipeline and the blob it handed out. */
@CompileStatic
final class Built {
    final Pipeline pipe
    final byte[] blob

    Built(Pipeline pipe, byte[] blob) {
        this.pipe = pipe
        this.blob = blob
    }
}

/** The outcome of flag resolution: a config, or an exit code with the
 * message already printed. */
@CompileStatic
final class Parsed {
    final Config cfg
    final int code

    Parsed(Config cfg, int code) {
        this.cfg = cfg
        this.code = code
    }
}

@CompileStatic
final class Main {

    private Main() {
    }

    /** --goroutines ceiling; the harness targets modest hosts and each
     * worker pins payload-sized buffers for the whole run. */
    static final int MAX_WORKERS = 10

    /** The concurrency mode this binding implements, as the summary
     * reports it (shared-handle / independent-handles / single). */
    static final String CONCURRENCY = 'shared-handle'

    /** Largest slice fed to a stream session per write; the drain
     * after every write uses the same bound. */
    static final int PUMP_SLICE = 1 << 20

    /** Profiles the shape-based pair is built against when --profile
     * is empty. */
    private static final String DEFAULT_STREAM_PROFILE = 'streaming-aead-triple-mac-v1'
    private static final String DEFAULT_MESSAGE_PROFILE = 'singlemsg-triple-mac-v1'

    /** The keystream-capable primitive supplied for a layer a profile
     * leaves unnamed: PRF-grade, so sound outside the barrier, and the
     * closest relative of the AES-based inner primitive whose profiles
     * need the fill. */
    private static final String KEYSTREAM_FILL_CIPHER = 'aescmac'

    /** The parallax segment size a filled palette runs with — the
     * library's own default; a schedule rejects zero. */
    private static final long KEYSTREAM_FILL_SEGMENT = 4093L

    /** Prints one prefixed status line to stdout. */
    static void logLine(String line) {
        System.out.println('[loop] ' + line)
    }

    static String onOff(boolean b) {
        b ? 'on' : 'off'
    }

    /** Renders an encoder policy env value for the summary: the raw
     * string when set, "default" when the shipped ladder applies. */
    static String policyLabel(String name) {
        String v = System.getenv(name)
        (v == null || v.trim().isEmpty()) ? 'default' : v.stripLeading()
    }

    private static String defaultOfLong(long v) {
        v != 0L ? " (default ${v})".toString() : ''
    }

    private static String defaultOfString(String v) {
        v.isEmpty() ? '' : " (default \"${v}\")".toString()
    }

    private static Long storeInt(String value) {
        try {
            return Long.valueOf(value)
        } catch (NumberFormatException e) {
            return null
        }
    }

    private static final List<Flag> FLAGS = buildFlags()

    private static List<Flag> buildFlags() {
        RawFlags d = new RawFlags()
        return [
            new Flag('barrier-fill', 'int',
                'DRBG barrier fill margin: 1 | 2 | 4 | 8 | 16 | 32; 0 = profile default (1)',
                false, defaultOfLong(d.barrierFill),
                { RawFlags f, String s -> Long v = storeInt(s); if (v == null) { return false }; f.barrierFill = v; true } as Closure<Boolean>),
            new Flag('blob-cycle-every', 'int',
                'reopen each pipeline from its session blob every N iterations per worker; 0 = never',
                false, '',
                { RawFlags f, String s -> Long v = storeInt(s); if (v == null) { return false }; f.blobCycleEvery = v; true } as Closure<Boolean>),
            new Flag('chunk-size', 'string',
                'streaming chunk-size budget (e.g. 4MB); 0 = profile default; inert for pure message shape',
                false, defaultOfString(d.chunkSize),
                { RawFlags f, String s -> f.chunkSize = s; true } as Closure<Boolean>),
            new Flag('duration', 'duration',
                'run duration (Go format: 30s / 5m / 1h); ignored when --iterations > 0',
                false, defaultOfString(d.duration),
                { RawFlags f, String s -> f.duration = s; true } as Closure<Boolean>),
            new Flag('gogc', 'int',
                'GC trigger percentage; 0 = leave the runtime default',
                false, defaultOfLong(d.gogc),
                { RawFlags f, String s -> Long v = storeInt(s); if (v == null) { return false }; f.gogc = v; true } as Closure<Boolean>),
            new Flag('gomaxprocs', 'int',
                'Go runtime GOMAXPROCS override; 0 = inherit from the environment',
                false, defaultOfLong(d.gomaxprocs),
                { RawFlags f, String s -> Long v = storeInt(s); if (v == null) { return false }; f.gomaxprocs = v; true } as Closure<Boolean>),
            new Flag('goroutines', 'int',
                'concurrent workers (1..10); on runtimes without parallelism values above 1 are clamped to 1',
                false, defaultOfLong(d.goroutines),
                { RawFlags f, String s -> Long v = storeInt(s); if (v == null) { return false }; f.goroutines = v; true } as Closure<Boolean>),
            new Flag('hash', 'string',
                'inner ITB hash primitive name',
                false, defaultOfString(d.hash),
                { RawFlags f, String s -> f.hash = s; true } as Closure<Boolean>),
            new Flag('iterations', 'int',
                'fixed per-worker iteration count; 0 = duration-based',
                false, '',
                { RawFlags f, String s -> Long v = storeInt(s); if (v == null) { return false }; f.iterations = v; true } as Closure<Boolean>),
            new Flag('json-output', '',
                'print the final summary as one compact JSON object instead of log lines',
                true, '',
                { RawFlags f, String s ->
                    if (s == 'true') { f.jsonOutput = true; return true }
                    if (s == 'false') { f.jsonOutput = false; return true }
                    false
                } as Closure<Boolean>),
            new Flag('key-bits', 'int',
                'per-seed key width in bits: 512 | 1024 | 2048; 0 = profile default (1024)',
                false, defaultOfLong(d.keyBits),
                { RawFlags f, String s -> Long v = storeInt(s); if (v == null) { return false }; f.keyBits = v; true } as Closure<Boolean>),
            new Flag('mac', 'string',
                'MAC primitive name',
                false, defaultOfString(d.mac),
                { RawFlags f, String s -> f.mac = s; true } as Closure<Boolean>),
            new Flag('memlimit', 'string',
                'Go heap soft limit: auto (1GiB when goroutines <= 3, else 256MiB, applied only when the runtime has no limit) or a size (e.g. 512MB)',
                false, defaultOfString(d.memlimit),
                { RawFlags f, String s -> f.memlimit = s; true } as Closure<Boolean>),
            new Flag('memprofile', 'string',
                'write a Go runtime heap profile (pprof) to this path at the end of the run; empty = none',
                false, defaultOfString(d.memprofile),
                { RawFlags f, String s -> f.memprofile = s; true } as Closure<Boolean>),
            new Flag('nonce-bits', 'int',
                'on-wire nonce width in bits: 128 | 256 | 512; 0 = profile default (512)',
                false, defaultOfLong(d.nonceBits),
                { RawFlags f, String s -> Long v = storeInt(s); if (v == null) { return false }; f.nonceBits = v; true } as Closure<Boolean>),
            new Flag('parallax', 'string',
                'parallax layer: on | off',
                false, defaultOfString(d.parallax),
                { RawFlags f, String s -> f.parallax = s; true } as Closure<Boolean>),
            new Flag('payload-mode', 'string',
                'plaintext content: fixed | rotating | pattern-zero | pattern-ff | pattern-ascii',
                false, defaultOfString(d.payloadMode),
                { RawFlags f, String s -> f.payloadMode = s; true } as Closure<Boolean>),
            new Flag('payload-size', 'string',
                'per-iteration plaintext size (e.g. 1MB / 16MB / 64MB)',
                false, defaultOfString(d.payloadSize),
                { RawFlags f, String s -> f.payloadSize = s; true } as Closure<Boolean>),
            new Flag('profile', 'string',
                "exercise this single registered triple profile (overrides --shape with the profile's surface); empty = shape-based profile pair",
                false, defaultOfString(d.profile),
                { RawFlags f, String s -> f.profile = s; true } as Closure<Boolean>),
            new Flag('rekey-every', 'int',
                'rotate the parallax + wrapper masters via Rekey every N iterations per worker; 0 = never',
                false, '',
                { RawFlags f, String s -> Long v = storeInt(s); if (v == null) { return false }; f.rekeyEvery = v; true } as Closure<Boolean>),
            new Flag('seed', 'uint',
                'deterministic plaintext RNG seed for bug reproduction, NOT for security testing (pipeline keys stay CSPRNG-drawn); 0 = crypto/rand plaintexts',
                false, '',
                { RawFlags f, String s ->
                    try {
                        f.seed = Long.parseUnsignedLong(s)
                    } catch (NumberFormatException e) {
                        return false
                    }
                    true
                } as Closure<Boolean>),
            new Flag('shape', 'string',
                'cipher surface to exercise: stream | message | stream_one_shot | both',
                false, defaultOfString(d.shape),
                { RawFlags f, String s -> f.shape = s; true } as Closure<Boolean>),
            new Flag('wrapper', 'string',
                'wrapper (Outer cipher) layer: on | off',
                false, defaultOfString(d.wrapper),
                { RawFlags f, String s -> f.wrapper = s; true } as Closure<Boolean>),
        ] as List<Flag>
    }

    private static void usage() {
        System.err.println('Usage of loop:')
        for (Flag fl : FLAGS) {
            System.err.println(fl.typeLabel.isEmpty()
                    ? '  -' + fl.name
                    : '  -' + fl.name + ' ' + fl.typeLabel)
            System.err.println('    \t' + fl.help + fl.defaultSuffix)
        }
    }

    /** Parses argv into the raw flag values. Accepts -name value,
     * --name value, -name=value and --name=value; a boolean flag takes
     * no value unless given as -name=true / -name=false. TRUE for -h /
     * --help (usage printed); null after printing the error. */
    private static Boolean parseArgv(String[] args, RawFlags f) {
        for (int i = 0; i < args.length; i++) {
            String arg = args[i]
            if (arg.length() <= 1 || arg.charAt(0) != ('-' as char)) {
                System.err.println("loop: unexpected positional arguments: [${arg}]")
                return null
            }
            String name = arg.startsWith('--') ? arg.substring(2) : arg.substring(1)
            if (name == 'h' || name == 'help') {
                usage()
                return Boolean.TRUE
            }
            String inline = null
            int eq = name.indexOf(((int) ('=' as char)))
            if (eq >= 0) {
                inline = name.substring(eq + 1)
                name = name.substring(0, eq)
            }
            Flag fl = null
            for (Flag candidate : FLAGS) {
                if (candidate.name == name) {
                    fl = candidate
                    break
                }
            }
            if (fl == null) {
                System.err.println("loop: flag provided but not defined: -${name}")
                usage()
                return null
            }
            String value
            if (inline != null) {
                value = inline
            } else if (fl.isBool) {
                value = 'true'
            } else {
                i++
                if (i >= args.length) {
                    System.err.println("loop: flag needs an argument: -${fl.name}")
                    return null
                }
                value = args[i]
            }
            if (!((Boolean) fl.store.call(f, value))) {
                System.err.println("loop: invalid value \"${value}\" for flag -${fl.name}")
                return null
            }
        }
        return Boolean.FALSE
    }

    /** Whether name is in the shipped hash registry the binding
     * returns. */
    private static boolean hashRegistered(String name) {
        try {
            return Pipeline.hashNames().contains(name)
        } catch (RuntimeException e) {
            return false
        }
    }

    /** Resolves a registered profile to the shape family its record's
     * mode exposes by reading the record through the binding's lookup:
     * a mode beginning with "streaming" exposes the stream surfaces,
     * one beginning with "singlemsg" the message surface, "blob-only"
     * none. Prints the validation message and returns null on
     * rejection. */
    private static Shape profileSurface(String name) {
        Profile p
        try {
            p = Pipeline.lookup(name)
        } catch (RuntimeException e) {
            System.err.println("loop: --profile \"${name}\" is not a registered triple profile")
            return null
        }
        if (p.mode().startsWith('streaming')) {
            return Shape.STREAM
        }
        if (p.mode().startsWith('singlemsg')) {
            return Shape.MESSAGE
        }
        System.err.println("loop: --profile \"${name}\" carries no cipher surface (blob-only mode)")
        return null
    }

    /** Applies a --profile's surface to the requested shape: a
     * message-surface profile forces message; a stream-surface profile
     * keeps stream or stream_one_shot as requested and turns message
     * or both into stream. */
    private static Shape narrowShape(Shape requested, Shape surface) {
        if (surface == Shape.MESSAGE) {
            return Shape.MESSAGE
        }
        return requested == Shape.STREAM_ONE_SHOT ? Shape.STREAM_ONE_SHOT : Shape.STREAM
    }

    /** Builds the resolved config from argv. Returns a null config
     * with code 0 for help and with code 2 after printing
     * "loop: &lt;message&gt;" for the first failing rule. */
    private static Parsed parseFlags(String[] args) {
        RawFlags f = new RawFlags()
        Boolean help = parseArgv(args, f)
        if (help == null) {
            return new Parsed(null, 2)
        }
        if (help.booleanValue()) {
            return new Parsed(null, 0)
        }
        Long durationNs = Size.parseDuration(f.duration)
        if (durationNs == null || durationNs <= 0L) {
            System.err.println("loop: --duration must be positive, got ${f.duration}")
            return new Parsed(null, 2)
        }
        if (f.iterations < 0) {
            System.err.println("loop: --iterations must be >= 0, got ${f.iterations}")
            return new Parsed(null, 2)
        }
        if (f.goroutines < 1 || f.goroutines > MAX_WORKERS) {
            System.err.println("loop: --goroutines must be in 1..${MAX_WORKERS}, got ${f.goroutines}")
            return new Parsed(null, 2)
        }
        // Concurrency mode. This binding runs shared-handle: JVM
        // platform threads call into one Pipeline handle concurrently.
        // The Groovy Pipeline is a thin lifetime wrapper holding one
        // Java Pipeline, which is itself a long over an opaque Go-side
        // registry key; every entry it is passed to is re-entrant
        // after construction, and the one piece of mutable machinery
        // behind it — the Java layer's pooled direct scratch pair — is
        // taken with an atomic swap so a concurrent caller falls back
        // to fresh buffers instead of sharing. So --goroutines is the
        // thread count verbatim, never clamped.
        int workers = (int) f.goroutines
        Shape shape = Worker.parseShape(f.shape)
        if (shape == null) {
            System.err.println('loop: --shape must be stream | message | stream_one_shot | both, ' +
                    "got \"${f.shape}\"")
            return new Parsed(null, 2)
        }
        if (!hashRegistered(f.hash)) {
            System.err.println("loop: --hash \"${f.hash}\" is not a registered hash primitive")
            return new Parsed(null, 2)
        }
        // --mac is validated by Init: the C ABI enumerates no MAC names.
        Long payload = Size.parseSize(f.payloadSize)
        if (payload == null) {
            System.err.println("loop: --payload-size: invalid size \"${f.payloadSize}\"")
            return new Parsed(null, 2)
        }
        if (payload < 1L) {
            System.err.println('loop: --payload-size must be at least 1 byte')
            return new Parsed(null, 2)
        }
        boolean memlimitAuto = f.memlimit == 'auto'
        long memlimit
        if (memlimitAuto) {
            memlimit = workers <= 3 ? 1L << 30 : 256L << 20
        } else {
            Long parsed = Size.parseSize(f.memlimit)
            if (parsed == null) {
                System.err.println("loop: --memlimit: invalid size \"${f.memlimit}\"")
                return new Parsed(null, 2)
            }
            memlimit = parsed
        }
        if (f.gogc < 0) {
            System.err.println("loop: --gogc must be >= 0, got ${f.gogc}")
            return new Parsed(null, 2)
        }
        boolean parallax
        if (f.parallax == 'on') {
            parallax = true
        } else if (f.parallax == 'off') {
            parallax = false
        } else {
            System.err.println("loop: --parallax must be on | off, got \"${f.parallax}\"")
            return new Parsed(null, 2)
        }
        boolean wrapper
        if (f.wrapper == 'on') {
            wrapper = true
        } else if (f.wrapper == 'off') {
            wrapper = false
        } else {
            System.err.println("loop: --wrapper must be on | off, got \"${f.wrapper}\"")
            return new Parsed(null, 2)
        }
        if (!f.profile.isEmpty()) {
            Shape surface = profileSurface(f.profile)
            if (surface == null) {
                return new Parsed(null, 2)
            }
            shape = narrowShape(shape, surface)
        }
        if (f.keyBits != 0L && f.keyBits != 512L && f.keyBits != 1024L && f.keyBits != 2048L) {
            System.err.println('loop: --key-bits must be 512 | 1024 | 2048 (or 0 = profile ' +
                    "default), got ${f.keyBits}")
            return new Parsed(null, 2)
        }
        if (f.nonceBits != 0L && f.nonceBits != 128L && f.nonceBits != 256L &&
                f.nonceBits != 512L) {
            System.err.println('loop: --nonce-bits must be 128 | 256 | 512 (or 0 = profile ' +
                    "default), got ${f.nonceBits}")
            return new Parsed(null, 2)
        }
        if (f.barrierFill != 0L && f.barrierFill != 1L && f.barrierFill != 2L &&
                f.barrierFill != 4L && f.barrierFill != 8L && f.barrierFill != 16L &&
                f.barrierFill != 32L) {
            System.err.println('loop: --barrier-fill must be 1 | 2 | 4 | 8 | 16 | 32 (or 0 = ' +
                    "profile default), got ${f.barrierFill}")
            return new Parsed(null, 2)
        }
        Long chunkSize = Size.parseSize(f.chunkSize)
        if (chunkSize == null) {
            System.err.println("loop: --chunk-size: invalid size \"${f.chunkSize}\"")
            return new Parsed(null, 2)
        }
        if (f.gomaxprocs < 0) {
            System.err.println("loop: --gomaxprocs must be > 0 when specified, got ${f.gomaxprocs}")
            return new Parsed(null, 2)
        }
        if (f.rekeyEvery < 0) {
            System.err.println("loop: --rekey-every must be >= 0, got ${f.rekeyEvery}")
            return new Parsed(null, 2)
        }
        if (f.blobCycleEvery < 0) {
            System.err.println("loop: --blob-cycle-every must be >= 0, got ${f.blobCycleEvery}")
            return new Parsed(null, 2)
        }
        PayloadMode payloadMode = Payload.parse(f.payloadMode)
        if (payloadMode == null) {
            System.err.println('loop: --payload-mode must be fixed | rotating | pattern-zero | ' +
                    "pattern-ff | pattern-ascii, got \"${f.payloadMode}\"")
            return new Parsed(null, 2)
        }
        Config cfg = new Config()
        cfg.durationNs = durationNs
        cfg.iterations = f.iterations
        cfg.workersRequested = workers
        cfg.workers = workers
        cfg.shape = shape
        cfg.hash = f.hash
        cfg.mac = f.mac
        cfg.payload = payload
        cfg.memlimit = memlimit
        cfg.memlimitAuto = memlimitAuto
        cfg.gogc = (int) f.gogc
        cfg.parallax = parallax
        cfg.wrapper = wrapper
        cfg.profile = f.profile
        cfg.keyBits = f.keyBits
        cfg.nonceBits = f.nonceBits
        cfg.chunkSize = chunkSize
        cfg.barrierFill = f.barrierFill
        cfg.gomaxprocs = (int) f.gomaxprocs
        cfg.rekeyEvery = f.rekeyEvery
        cfg.blobCycleEvery = f.blobCycleEvery
        cfg.payloadMode = payloadMode
        cfg.seed = f.seed
        cfg.jsonOutput = f.jsonOutput
        cfg.memprofile = f.memprofile
        return new Parsed(cfg, 0)
    }

    private static volatile boolean signalSeen

    /** Counted down once the summary has been emitted, so the shutdown
     * hook can hold the JVM's own termination back until then. */
    private static final CountDownLatch SUMMARY_DONE = new CountDownLatch(1)

    /**
     * Graceful stop. SIGINT / SIGTERM set a flag the main thread polls
     * while it waits for the workers; it turns the flag into the stop
     * request every worker checks before starting an iteration, so a
     * signal interrupts nothing mid-call — the in-flight encrypt /
     * decrypt / compare completes, the worker returns, and the partial
     * summary prints with the verdict the completed iterations earned.
     * Groovy-specific: the supported way to observe a termination
     * signal on this runtime is a shutdown hook, which runs
     * concurrently with the main thread rather than in place of it and
     * cannot set the exit code, so the hook only raises the flag and
     * then blocks until the summary is out; the verdict's code is then
     * delivered by halting the runtime from the main thread, which is
     * also what makes the exit code the verdict's rather than the
     * JVM's own signal code.
     */
    private static void installSignals() {
        Thread hook = new Thread({
            signalSeen = true
            try {
                SUMMARY_DONE.await(2L, TimeUnit.MINUTES)
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt()
            }
        } as Runnable, 'loop-signal')
        java.lang.Runtime.getRuntime().addShutdownHook(hook)
    }

    /**
     * Supplies the keystream-capable primitive for every layer the
     * profile record leaves unnamed and the run engages: a missing
     * parallax palette becomes three copies of the fill cipher (with
     * the library's default segment size when the record carries
     * none), a missing outer cipher becomes the fill cipher. These are
     * opts overrides that fold into the resolved record the blob
     * carries — a derived profile is never registered, so no name the
     * receiver did not agree to reaches the wire. Null after printing
     * the validation message.
     */
    private static Filled fillKeystreamLayers(String name, Opts opts, boolean wantParallax,
            boolean wantWrapper) {
        Profile p
        try {
            p = Pipeline.lookup(name)
        } catch (RuntimeException e) {
            System.err.println("loop: --profile \"${name}\" is not a registered triple profile")
            return null
        }
        boolean filled = false
        Opts out = opts
        if (wantParallax && p.palette().isEmpty()) {
            out = out.withParallaxPalette(KEYSTREAM_FILL_CIPHER, KEYSTREAM_FILL_CIPHER,
                    KEYSTREAM_FILL_CIPHER)
            if (p.segment() == 0) {
                // A recipe that never carried a palette never carried a
                // segment size either, and the schedule rejects zero.
                out = out.withParallaxSegmentSize(KEYSTREAM_FILL_SEGMENT)
            }
            filled = true
        }
        if (wantWrapper && p.outer().isEmpty()) {
            out = out.withOuterCipher(KEYSTREAM_FILL_CIPHER)
            filled = true
        }
        return new Filled(out, filled)
    }

    /**
     * Constructs one Pipeline against profile with every flag-carried
     * override in the opts string (zero values included — the shared
     * library treats zero as "profile default"), then obtains the Init
     * blob once through save: the binding's init entry does not hand
     * the blob back, and the bytes are the ones Init produced. Later
     * blob reopens use the retained blob; save is never called again.
     */
    private static Built buildPipeline(Config cfg, String profile) {
        Opts opts = new Opts()
                .withInnerHash(cfg.hash)
                .withMacName(cfg.mac)
                .withParallax(cfg.parallax)
                .withWrapper(cfg.wrapper)
                .withKeyBits(cfg.keyBits)
                .withNonceBits(cfg.nonceBits)
                .withBarrierFill(cfg.barrierFill)
                .withChunkSize(cfg.chunkSize)
        if (!cfg.profile.isEmpty()) {
            Filled filled = fillKeystreamLayers(cfg.profile, opts, cfg.parallax, cfg.wrapper)
            if (filled == null) {
                return null
            }
            opts = filled.opts
            if (filled.filled) {
                System.err.println("loop: ${cfg.profile} leaves the requested keystream layers " +
                        "unnamed; ${KEYSTREAM_FILL_CIPHER} supplied for them")
            }
        }
        Pipeline pipe
        try {
            pipe = Pipeline.init(profile, opts)
        } catch (RuntimeException e) {
            System.err.println("loop: Init(${profile}): ${Worker.detail(e)}")
            return null
        }
        byte[] blob
        try {
            blob = pipe.save()
        } catch (RuntimeException e) {
            System.err.println("loop: Save(${profile}): ${Worker.detail(e)}")
            pipe.close()
            return null
        }
        logPipelineInitialised(profile, blob)
        return new Built(pipe, blob)
    }

    private static String dash(String s) {
        s.isEmpty() ? '-' : s
    }

    /** Prints the construction line with the recipe read back from the
     * blob the Pipeline handed out, not echoed from the flags: every
     * construction override is proven to have reached the library by
     * the value the receiver would see. Record values that are empty
     * (a No MAC profile's MAC, a mixed profile's single hash) print as
     * "-". */
    private static void logPipelineInitialised(String profile, byte[] blob) {
        Profile rec
        try {
            rec = Pipeline.inspect(blob)
        } catch (RuntimeException e) {
            logLine("pipeline initialised: profile=${profile} blob=${blob.length} bytes " +
                    "(inspect: ${Worker.detail(e)})")
            return
        }
        logLine("pipeline initialised: profile=${profile} blob=${blob.length} bytes" +
                " hash=${dash(rec.hash())}" +
                " key-bits=${rec.keyBits()}" +
                " nonce-bits=${rec.nonceBits() == null ? 0 : rec.nonceBits()}" +
                " barrier-fill=${rec.barrierFill() == null ? 0 : rec.barrierFill()}" +
                " chunk-size=${rec.chunk()}" +
                " mac=${dash(rec.mac())}" +
                " parallax=${onOff(rec.parallax())}" +
                " wrapper=${onOff(rec.wrapper())}")
    }

    private static int run(String[] args) {
        Parsed parsed = parseFlags(args)
        Config cfg = parsed.cfg
        if (cfg == null) {
            return parsed.code
        }

        // Runtime shaping. A long run under allocation churn grows the
        // Go heap inside the shared library without bound unless a
        // soft limit paces the collector, so a limit is always in
        // force: an explicit --memlimit is set as given, and auto caps
        // the heap only when the runtime reports no limit at all (a
        // limit already installed from the environment is left
        // standing). The GC percentage and GOMAXPROCS are set only
        // when their flag is non-zero — a zero flag skips the setter
        // rather than calling it with zero, because zero is a real
        // value to the GC-percent setter, and a call would clobber
        // whatever the environment installed. All of it lands before
        // any Pipeline exists so the baselines are taken under the
        // shaped runtime.
        if (cfg.memlimitAuto) {
            if (ItbRuntime.setMemoryLimit(-1L) == Long.MAX_VALUE) {
                ItbRuntime.setMemoryLimit(cfg.memlimit)
            }
        } else {
            ItbRuntime.setMemoryLimit(cfg.memlimit)
        }
        cfg.memlimit = ItbRuntime.setMemoryLimit(-1L)
        if (cfg.gogc > 0) {
            ItbRuntime.setGCPercent(cfg.gogc)
        }
        if (cfg.gomaxprocs > 0) {
            ItbRuntime.setGOMAXPROCS(cfg.gomaxprocs)
        }

        logLine("start: duration=${Size.humanDuration(cfg.durationNs)}" +
                " iterations=${cfg.iterations}" +
                " goroutines=${cfg.workersRequested}" +
                " workers=${cfg.workers}" +
                " concurrency=${CONCURRENCY}" +
                " shape=${cfg.shape.label}" +
                " hash=${cfg.hash}" +
                " mac=${cfg.mac}" +
                " payload=${Size.humanBytes(cfg.payload)}" +
                " memlimit=${Size.humanBytes(cfg.memlimit)}" +
                " parallax=${onOff(cfg.parallax)}" +
                " wrapper=${onOff(cfg.wrapper)}")
        logLine("overrides: profile=\"${cfg.profile}\"" +
                " key-bits=${cfg.keyBits}" +
                " nonce-bits=${cfg.nonceBits}" +
                " chunk-size=${Size.humanBytes(cfg.chunkSize)}" +
                " barrier-fill=${cfg.barrierFill}" +
                " gomaxprocs=${cfg.gomaxprocs}" +
                " rekey-every=${cfg.rekeyEvery}" +
                " blob-cycle-every=${cfg.blobCycleEvery}" +
                " payload-mode=${cfg.payloadMode.label}" +
                " seed=${Long.toUnsignedString(cfg.seed)}" +
                " json-output=${cfg.jsonOutput ? 'true' : 'false'}")
        logLine("policy: microbatch-tiers=${policyLabel('ITB_MICROBATCH_TIERS')}" +
                " hashpool-starters=${policyLabel('ITB_HASHPOOL_STARTERS')}")

        // Pipeline construction — one shared handle per exercised
        // shape. stream and stream_one_shot share the streaming handle.
        String streamProfile = cfg.profile.isEmpty() ? DEFAULT_STREAM_PROFILE : cfg.profile
        String msgProfile = cfg.profile.isEmpty() ? DEFAULT_MESSAGE_PROFILE : cfg.profile
        Pipes pipes = new Pipes()
        if (cfg.shape == Shape.STREAM || cfg.shape == Shape.STREAM_ONE_SHOT ||
                cfg.shape == Shape.BOTH) {
            Built built = buildPipeline(cfg, streamProfile)
            if (built == null) {
                return 1
            }
            pipes.stream = built.pipe
            pipes.streamBlob = built.blob
        }
        if (cfg.shape == Shape.MESSAGE || cfg.shape == Shape.BOTH) {
            Built built = buildPipeline(cfg, msgProfile)
            if (built == null) {
                return 1
            }
            pipes.msg = built.pipe
            pipes.msgBlob = built.blob
        }

        // Allocation posture. Per-worker plaintexts are allocated once
        // and held for the whole run (rotating mode refills them in
        // place per iteration); the pump accumulators and the drain
        // scratch live inside each worker and are reused across
        // iterations; the message and one-shot outputs are allocated
        // by the binding per call and reclaimed per iteration. Under
        // the default fixed CSPRNG mode every worker's buffer is
        // distinct, so cross-worker data crossover is detectable;
        // pattern modes trade that property for content edge-case
        // coverage.
        if (cfg.payload > ((long) Integer.MAX_VALUE) - 8L) {
            System.err.println('loop: --payload-size exceeds the largest JVM array')
            return 1
        }
        List<WorkerState> states = new ArrayList<WorkerState>(cfg.workers)
        for (int id = 0; id < cfg.workers; id++) {
            WorkerState w = new WorkerState()
            w.id = id
            w.plaintext = new byte[(int) cfg.payload]
            w.payloadMode = cfg.payloadMode
            w.seeded = cfg.seed != 0L
            w.rng = new Rng(Payload.seedWorker(cfg.seed, id))
            w.scratch = new byte[PUMP_SLICE]
            if (!Payload.fill(cfg.payloadMode, w.seeded, w.rng, w.plaintext)) {
                System.err.println('loop: payload fill: csprng')
                return 1
            }
            states.add(w)
        }

        installSignals()
        RunState r = new RunState()
        r.cfg = cfg
        r.streamProfile = streamProfile
        r.msgProfile = msgProfile
        r.pipes = pipes
        r.workers = new Counters[cfg.workers]
        for (int i = 0; i < cfg.workers; i++) {
            r.workers[i] = new Counters()
        }
        r.warmupDone = new CyclicBarrier(cfg.workers + 1)
        r.release = new CyclicBarrier(cfg.workers + 1)
        r.active = cfg.workers

        // Warmup barrier. Every worker runs one iteration and waits;
        // the clock starts only once all of them have paid their
        // first-call costs (pool warm-up, lazy kernel dispatch, page
        // faults on the payload buffers, and on this runtime the
        // tiered JIT's first pass over the iteration body), and the
        // RSS and pool baselines taken here describe a process that
        // has already run the whole cipher path once per worker.
        long warmupStart = System.nanoTime()
        List<Thread> threads = new ArrayList<Thread>(cfg.workers)
        for (WorkerState state : states) {
            // Groovy-specific. A closure captures the variable, not
            // its value, and a `for` header declares one variable for
            // the whole loop — every thread would share the last
            // element. Re-binding inside the body gives each closure
            // its own capture.
            final WorkerState w = state
            Thread t = new Thread({ Worker.run(r, w) } as Runnable, "loop-worker-${w.id}")
            t.setDaemon(false)
            threads.add(t)
            t.start()
        }
        try {
            r.warmupDone.await()
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt()
            System.err.println("loop: warmup barrier: ${e}")
            return 1
        } catch (BrokenBarrierException e) {
            System.err.println("loop: warmup barrier: ${e}")
            return 1
        }
        long[] rss = Summary.readRss()
        long rssWarmup = rss[0]
        long[] poolWarmup = Summary.poolSnapshot()
        logLine("warmup: ${cfg.workers} workers x 1 iter completed in " +
                Size.humanDuration(Size.roundTo(System.nanoTime() - warmupStart, 100_000_000L)) +
                " (baseline rss=${Size.humanBytes(rssWarmup)})")

        // Open the gate; the duration is a deadline the waiter below
        // enforces in duration mode.
        long start = System.nanoTime()
        try {
            r.release.await()
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt()
            System.err.println("loop: release barrier: ${e}")
            return 1
        } catch (BrokenBarrierException e) {
            System.err.println("loop: release barrier: ${e}")
            return 1
        }

        // Wait for every worker, polling every 100 ms so the deadline
        // and a signal are both noticed promptly.
        long finish = start
        r.doneLock.lock()
        try {
            while (r.active > 0) {
                if (signalSeen || (cfg.iterations == 0L &&
                        System.nanoTime() - start >= cfg.durationNs)) {
                    r.stop = true
                }
                try {
                    r.doneCond.await(100L, TimeUnit.MILLISECONDS)
                } catch (InterruptedException e) {
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
        long elapsedNs = finish - start
        long[] rssEnd = Summary.readRss()
        long[] poolSteady = Summary.poolSnapshot()
        for (Thread t : threads) {
            try {
                t.join()
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt()
            }
        }
        r.rssWarmup = rssWarmup
        r.rssFinal = rssEnd[0]
        r.rssPeak = rssEnd[1]
        r.poolWarmup = poolWarmup
        r.poolSteady = poolSteady

        if (!cfg.memprofile.isEmpty()) {
            try {
                ItbRuntime.writeHeapProfile(cfg.memprofile)
                logLine("memprofile: heap profile written to ${cfg.memprofile}")
            } catch (RuntimeException e) {
                System.err.println("loop: memprofile: ${Worker.detail(e)}")
            }
        }

        int exit = Summary.emit(r, elapsedNs)
        if (r.pipes.stream != null) {
            r.pipes.stream.close()
        }
        if (r.pipes.msg != null) {
            r.pipes.msg.close()
        }
        return exit
    }

    /** Restores the default disposition of SIGPIPE.
     *
     * Groovy-specific. The runtime ignores the signal and the standard
     * streams swallow the write error that replaces it, so a consumer
     * that stops reading leaves the process printing into nothing and
     * exiting 0 with its verdict undelivered. With the default
     * disposition back the first such write ends the process, which is
     * what every other implementation does and what a fleet driver
     * expects. */
    static void restoreSigpipe() {
        sun.misc.Signal.handle(new sun.misc.Signal('PIPE'), sun.misc.SignalHandler.SIG_DFL)
    }

    /** Entry point. */
    static void main(String[] args) {
        restoreSigpipe()
        int code = run(args)
        System.out.flush()
        System.err.flush()
        SUMMARY_DONE.countDown()
        // Groovy-specific. The verdict's code is delivered by halting
        // the runtime rather than by returning from main: when a
        // signal has started the shutdown sequence, returning would
        // let the JVM finish that sequence with its own signal-derived
        // code instead of this one.
        java.lang.Runtime.getRuntime().halt(code)
    }
}
