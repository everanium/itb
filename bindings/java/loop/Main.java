// Long-run stress harness. The loop utility holds one Pipeline handle
// per exercised cipher surface for minutes, hammers it with concurrent
// encrypt → decrypt → compare round-trips from N worker threads,
// rotates the outer masters and reopens the handle from its session
// blob on a schedule, and reports whether the process survived with
// every byte intact. It is the Java binding's counterpart of the Go
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
// for. This binding runs a Go c-shared runtime and a HotSpot JVM in
// one process, two runtimes that each drive threads through signals
// and each collect their own heap, which is the interaction the long
// run is meant to expose.
//
// Usage:
//
//   java -jar build/libs/loop.jar --duration 5m --goroutines 3 \
//          --shape stream --hash areion512 --mac hmac-blake3 \
//          --payload-size 16MB --memlimit auto --parallax on --wrapper on
//
// Ctrl-C triggers a graceful shutdown: in-flight iterations complete,
// then the partial summary prints.

package io.github.everanium.itb3.loop;

import io.github.everanium.itb3.ItbException;
import io.github.everanium.itb3.Opts;
import io.github.everanium.itb3.Pipeline;
import io.github.everanium.itb3.Profile;
import io.github.everanium.itb3.Runtime;
import io.github.everanium.itb3.loop.Payload.PayloadMode;
import io.github.everanium.itb3.loop.State.Config;
import io.github.everanium.itb3.loop.State.Counters;
import io.github.everanium.itb3.loop.State.Pipes;
import io.github.everanium.itb3.loop.State.RunState;
import io.github.everanium.itb3.loop.State.WorkerState;
import io.github.everanium.itb3.loop.Worker.Shape;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/** The loop stress harness entry point. */
public final class Main {

    private Main() {
    }

    /** --goroutines ceiling; the harness targets modest hosts and each
     * worker pins payload-sized buffers for the whole run. */
    static final int MAX_WORKERS = 10;

    /** The concurrency mode this binding implements, as the summary
     * reports it (shared-handle / independent-handles / single). */
    static final String CONCURRENCY = "shared-handle";

    /** Largest slice fed to a stream session per write; the drain after
     * every write uses the same bound. */
    static final int PUMP_SLICE = 1 << 20;

    /** Profiles the shape-based pair is built against when --profile is
     * empty. */
    private static final String DEFAULT_STREAM_PROFILE = "streaming-aead-triple-mac-v1";
    private static final String DEFAULT_MESSAGE_PROFILE = "singlemsg-triple-mac-v1";

    /** The keystream-capable primitive supplied for a layer a profile
     * leaves unnamed: PRF-grade, so sound outside the barrier, and the
     * closest relative of the AES-based inner primitive whose profiles
     * need the fill. */
    private static final String KEYSTREAM_FILL_CIPHER = "aescmac";

    /** The parallax segment size a filled palette runs with — the
     * library's own default; a schedule rejects zero. */
    private static final long KEYSTREAM_FILL_SEGMENT = 4093;

    /** Prints one prefixed status line to stdout. */
    static void logLine(String line) {
        System.out.println("[loop] " + line);
    }

    static String onOff(boolean b) {
        return b ? "on" : "off";
    }

    /** Renders an encoder policy env value for the summary: the raw
     * string when set, "default" when the shipped ladder applies. */
    static String policyLabel(String name) {
        String v = System.getenv(name);
        return v == null || v.isBlank() ? "default" : v.stripLeading();
    }

    // ------------------------------------------------------------------
    // Flags
    // ------------------------------------------------------------------

    /** The raw flag values before validation. */
    private static final class RawFlags {
        long barrierFill;
        long blobCycleEvery;
        String chunkSize = "0";
        String duration = "5m";
        long gogc;
        long gomaxprocs;
        long goroutines = 3;
        String hash = "areion512";
        long iterations;
        boolean jsonOutput;
        long keyBits;
        String mac = "hmac-blake3";
        String memlimit = "auto";
        String memprofile = "";
        long nonceBits;
        String parallax = "on";
        String payloadMode = "fixed";
        String payloadSize = "16MB";
        String profile = "";
        long rekeyEvery;
        long seed;
        String shape = "stream";
        String wrapper = "on";
    }

    /** Parses one flag value into the raw flags; false on a malformed
     * value. */
    private interface Store {
        boolean store(RawFlags f, String value);
    }

    /** One command-line flag: its name, the type label the usage
     * prints, its help text, whether it takes a value, the
     * default-value suffix the usage appends, and the store that parses
     * a value into the raw flags. Values are validated after the whole
     * line is parsed. The table is in alphabetical order — the order
     * the usage prints. */
    private record Flag(String name, String typeLabel, String help, boolean isBool,
            String defaultSuffix, Store store) {
    }

    private static String defaultOf(long v) {
        return v != 0 ? " (default " + v + ")" : "";
    }

    private static String defaultOf(String v) {
        return v.isEmpty() ? "" : " (default \"" + v + "\")";
    }

    /** Parses a signed decimal; out-of-range and malformed both fail. */
    private static Long storeInt(String value) {
        try {
            return Long.valueOf(value);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static final Flag[] FLAGS = buildFlags();

    private static Flag[] buildFlags() {
        RawFlags d = new RawFlags();
        return new Flag[] {
            new Flag("barrier-fill", "int",
                    "DRBG barrier fill margin: 1 | 2 | 4 | 8 | 16 | 32; 0 = profile default (1)",
                    false, defaultOf(d.barrierFill),
                    (f, s) -> {
                        Long v = storeInt(s);
                        if (v == null) {
                            return false;
                        }
                        f.barrierFill = v;
                        return true;
                    }),
            new Flag("blob-cycle-every", "int",
                    "reopen each pipeline from its session blob every N iterations per worker;"
                            + " 0 = never",
                    false, "",
                    (f, s) -> {
                        Long v = storeInt(s);
                        if (v == null) {
                            return false;
                        }
                        f.blobCycleEvery = v;
                        return true;
                    }),
            new Flag("chunk-size", "string",
                    "streaming chunk-size budget (e.g. 4MB); 0 = profile default; inert for pure"
                            + " message shape",
                    false, defaultOf(d.chunkSize),
                    (f, s) -> {
                        f.chunkSize = s;
                        return true;
                    }),
            new Flag("duration", "duration",
                    "run duration (Go format: 30s / 5m / 1h); ignored when --iterations > 0",
                    false, defaultOf(d.duration),
                    (f, s) -> {
                        f.duration = s;
                        return true;
                    }),
            new Flag("gogc", "int",
                    "GC trigger percentage; 0 = leave the runtime default",
                    false, defaultOf(d.gogc),
                    (f, s) -> {
                        Long v = storeInt(s);
                        if (v == null) {
                            return false;
                        }
                        f.gogc = v;
                        return true;
                    }),
            new Flag("gomaxprocs", "int",
                    "Go runtime GOMAXPROCS override; 0 = inherit from the environment",
                    false, defaultOf(d.gomaxprocs),
                    (f, s) -> {
                        Long v = storeInt(s);
                        if (v == null) {
                            return false;
                        }
                        f.gomaxprocs = v;
                        return true;
                    }),
            new Flag("goroutines", "int",
                    "concurrent workers (1..10); on runtimes without parallelism values above 1"
                            + " are clamped to 1",
                    false, defaultOf(d.goroutines),
                    (f, s) -> {
                        Long v = storeInt(s);
                        if (v == null) {
                            return false;
                        }
                        f.goroutines = v;
                        return true;
                    }),
            new Flag("hash", "string",
                    "inner ITB hash primitive name",
                    false, defaultOf(d.hash),
                    (f, s) -> {
                        f.hash = s;
                        return true;
                    }),
            new Flag("iterations", "int",
                    "fixed per-worker iteration count; 0 = duration-based",
                    false, "",
                    (f, s) -> {
                        Long v = storeInt(s);
                        if (v == null) {
                            return false;
                        }
                        f.iterations = v;
                        return true;
                    }),
            new Flag("json-output", "",
                    "print the final summary as one compact JSON object instead of log lines",
                    true, "",
                    (f, s) -> {
                        if ("true".equals(s)) {
                            f.jsonOutput = true;
                            return true;
                        }
                        if ("false".equals(s)) {
                            f.jsonOutput = false;
                            return true;
                        }
                        return false;
                    }),
            new Flag("key-bits", "int",
                    "per-seed key width in bits: 512 | 1024 | 2048; 0 = profile default (1024)",
                    false, defaultOf(d.keyBits),
                    (f, s) -> {
                        Long v = storeInt(s);
                        if (v == null) {
                            return false;
                        }
                        f.keyBits = v;
                        return true;
                    }),
            new Flag("mac", "string",
                    "MAC primitive name",
                    false, defaultOf(d.mac),
                    (f, s) -> {
                        f.mac = s;
                        return true;
                    }),
            new Flag("memlimit", "string",
                    "Go heap soft limit: auto (1GiB when goroutines <= 3, else 256MiB, applied"
                            + " only when the runtime has no limit) or a size (e.g. 512MB)",
                    false, defaultOf(d.memlimit),
                    (f, s) -> {
                        f.memlimit = s;
                        return true;
                    }),
            new Flag("memprofile", "string",
                    "write a Go runtime heap profile (pprof) to this path at the end of the run;"
                            + " empty = none",
                    false, defaultOf(d.memprofile),
                    (f, s) -> {
                        f.memprofile = s;
                        return true;
                    }),
            new Flag("nonce-bits", "int",
                    "on-wire nonce width in bits: 128 | 256 | 512; 0 = profile default (512)",
                    false, defaultOf(d.nonceBits),
                    (f, s) -> {
                        Long v = storeInt(s);
                        if (v == null) {
                            return false;
                        }
                        f.nonceBits = v;
                        return true;
                    }),
            new Flag("parallax", "string",
                    "parallax layer: on | off",
                    false, defaultOf(d.parallax),
                    (f, s) -> {
                        f.parallax = s;
                        return true;
                    }),
            new Flag("payload-mode", "string",
                    "plaintext content: fixed | rotating | pattern-zero | pattern-ff |"
                            + " pattern-ascii",
                    false, defaultOf(d.payloadMode),
                    (f, s) -> {
                        f.payloadMode = s;
                        return true;
                    }),
            new Flag("payload-size", "string",
                    "per-iteration plaintext size (e.g. 1MB / 16MB / 64MB)",
                    false, defaultOf(d.payloadSize),
                    (f, s) -> {
                        f.payloadSize = s;
                        return true;
                    }),
            new Flag("profile", "string",
                    "exercise this single registered triple profile (overrides --shape with the"
                            + " profile's surface); empty = shape-based profile pair",
                    false, defaultOf(d.profile),
                    (f, s) -> {
                        f.profile = s;
                        return true;
                    }),
            new Flag("rekey-every", "int",
                    "rotate the parallax + wrapper masters via Rekey every N iterations per"
                            + " worker; 0 = never",
                    false, "",
                    (f, s) -> {
                        Long v = storeInt(s);
                        if (v == null) {
                            return false;
                        }
                        f.rekeyEvery = v;
                        return true;
                    }),
            new Flag("seed", "uint",
                    "deterministic plaintext RNG seed for bug reproduction, NOT for security"
                            + " testing (pipeline keys stay CSPRNG-drawn); 0 = crypto/rand"
                            + " plaintexts",
                    false, "",
                    (f, s) -> {
                        try {
                            f.seed = Long.parseUnsignedLong(s);
                        } catch (NumberFormatException e) {
                            return false;
                        }
                        return true;
                    }),
            new Flag("shape", "string",
                    "cipher surface to exercise: stream | message | stream_one_shot | both",
                    false, defaultOf(d.shape),
                    (f, s) -> {
                        f.shape = s;
                        return true;
                    }),
            new Flag("wrapper", "string",
                    "wrapper (Outer cipher) layer: on | off",
                    false, defaultOf(d.wrapper),
                    (f, s) -> {
                        f.wrapper = s;
                        return true;
                    }),
        };
    }

    private static void usage() {
        System.err.println("Usage of loop:");
        for (Flag fl : FLAGS) {
            System.err.println(fl.typeLabel().isEmpty()
                    ? "  -" + fl.name()
                    : "  -" + fl.name() + " " + fl.typeLabel());
            System.err.println("    \t" + fl.help() + fl.defaultSuffix());
        }
    }

    /** Parses argv into the raw flag values. Accepts -name value, --name
     * value, -name=value and --name=value; a boolean flag takes no
     * value unless given as -name=true / -name=false. TRUE for -h /
     * --help (usage printed); null after printing the error. */
    private static Boolean parseArgv(String[] args, RawFlags f) {
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (arg.length() <= 1 || arg.charAt(0) != '-') {
                System.err.println("loop: unexpected positional arguments: [" + arg + "]");
                return null;
            }
            String name = arg.startsWith("--") ? arg.substring(2) : arg.substring(1);
            if (name.equals("h") || name.equals("help")) {
                usage();
                return Boolean.TRUE;
            }
            String inline = null;
            int eq = name.indexOf('=');
            if (eq >= 0) {
                inline = name.substring(eq + 1);
                name = name.substring(0, eq);
            }
            Flag fl = null;
            for (Flag candidate : FLAGS) {
                if (candidate.name().equals(name)) {
                    fl = candidate;
                    break;
                }
            }
            if (fl == null) {
                System.err.println("loop: flag provided but not defined: -" + name);
                usage();
                return null;
            }
            String value;
            if (inline != null) {
                value = inline;
            } else if (fl.isBool()) {
                value = "true";
            } else {
                i++;
                if (i >= args.length) {
                    System.err.println("loop: flag needs an argument: -" + fl.name());
                    return null;
                }
                value = args[i];
            }
            if (!fl.store().store(f, value)) {
                System.err.println(
                        "loop: invalid value \"" + value + "\" for flag -" + fl.name());
                return null;
            }
        }
        return Boolean.FALSE;
    }

    /** Whether name is in the shipped hash registry the binding
     * returns. */
    private static boolean hashRegistered(String name) {
        try {
            return Pipeline.hashNames().contains(name);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** Resolves a registered profile to the shape family its record's
     * mode exposes by reading the record through the binding's lookup: a
     * mode beginning with "streaming" exposes the stream surfaces, one
     * beginning with "singlemsg" the message surface, "blob-only" none.
     * Prints the validation message and returns null on rejection. */
    private static Shape profileSurface(String name) {
        Profile p;
        try {
            p = Pipeline.lookup(name);
        } catch (RuntimeException e) {
            System.err.println(
                    "loop: --profile \"" + name + "\" is not a registered triple profile");
            return null;
        }
        if (p.mode().startsWith("streaming")) {
            return Shape.STREAM;
        }
        if (p.mode().startsWith("singlemsg")) {
            return Shape.MESSAGE;
        }
        System.err.println(
                "loop: --profile \"" + name + "\" carries no cipher surface (blob-only mode)");
        return null;
    }

    /** Applies a --profile's surface to the requested shape: a
     * message-surface profile forces message; a stream-surface profile
     * keeps stream or stream_one_shot as requested and turns message or
     * both into stream. */
    private static Shape narrowShape(Shape requested, Shape surface) {
        if (surface == Shape.MESSAGE) {
            return Shape.MESSAGE;
        }
        return requested == Shape.STREAM_ONE_SHOT ? Shape.STREAM_ONE_SHOT : Shape.STREAM;
    }

    /** The outcome of flag resolution: a config, or an exit code with
     * the message already printed. */
    private static final class Parsed {
        final Config cfg;
        final int code;

        Parsed(Config cfg, int code) {
            this.cfg = cfg;
            this.code = code;
        }
    }

    /** Builds the resolved config from argv. Returns a null config with
     * code 0 for help and with code 2 after printing "loop: &lt;message&gt;"
     * for the first failing rule. */
    private static Parsed parseFlags(String[] args) {
        RawFlags f = new RawFlags();
        Boolean help = parseArgv(args, f);
        if (help == null) {
            return new Parsed(null, 2);
        }
        if (help.booleanValue()) {
            return new Parsed(null, 0);
        }
        Long durationNs = Size.parseDuration(f.duration);
        if (durationNs == null || durationNs <= 0) {
            System.err.println("loop: --duration must be positive, got " + f.duration);
            return new Parsed(null, 2);
        }
        if (f.iterations < 0) {
            System.err.println("loop: --iterations must be >= 0, got " + f.iterations);
            return new Parsed(null, 2);
        }
        if (f.goroutines < 1 || f.goroutines > MAX_WORKERS) {
            System.err.println("loop: --goroutines must be in 1.." + MAX_WORKERS
                    + ", got " + f.goroutines);
            return new Parsed(null, 2);
        }
        // Concurrency mode. This binding runs shared-handle: JVM
        // platform threads call into one Pipeline handle concurrently.
        // The handle is a Java long over an opaque Go-side registry key,
        // every entry it is passed to is re-entrant after construction,
        // and the binding's Pipeline holds no thread-affine state — its
        // one piece of mutable machinery, the pooled direct scratch
        // pair, is taken with an atomic swap so a concurrent caller
        // falls back to fresh buffers instead of sharing. So
        // --goroutines is the thread count verbatim, never clamped.
        int workers = (int) f.goroutines;
        Shape shape = Worker.parseShape(f.shape);
        if (shape == null) {
            System.err.println("loop: --shape must be stream | message | stream_one_shot | both,"
                    + " got \"" + f.shape + "\"");
            return new Parsed(null, 2);
        }
        if (!hashRegistered(f.hash)) {
            System.err.println(
                    "loop: --hash \"" + f.hash + "\" is not a registered hash primitive");
            return new Parsed(null, 2);
        }
        // --mac is validated by Init: the C ABI enumerates no MAC names.
        Long payload = Size.parseSize(f.payloadSize);
        if (payload == null) {
            System.err.println("loop: --payload-size: invalid size \"" + f.payloadSize + "\"");
            return new Parsed(null, 2);
        }
        if (payload < 1) {
            System.err.println("loop: --payload-size must be at least 1 byte");
            return new Parsed(null, 2);
        }
        boolean memlimitAuto = "auto".equals(f.memlimit);
        long memlimit;
        if (memlimitAuto) {
            memlimit = workers <= 3 ? 1L << 30 : 256L << 20;
        } else {
            Long parsed = Size.parseSize(f.memlimit);
            if (parsed == null) {
                System.err.println("loop: --memlimit: invalid size \"" + f.memlimit + "\"");
                return new Parsed(null, 2);
            }
            memlimit = parsed;
        }
        if (f.gogc < 0) {
            System.err.println("loop: --gogc must be >= 0, got " + f.gogc);
            return new Parsed(null, 2);
        }
        boolean parallax;
        if ("on".equals(f.parallax)) {
            parallax = true;
        } else if ("off".equals(f.parallax)) {
            parallax = false;
        } else {
            System.err.println("loop: --parallax must be on | off, got \"" + f.parallax + "\"");
            return new Parsed(null, 2);
        }
        boolean wrapper;
        if ("on".equals(f.wrapper)) {
            wrapper = true;
        } else if ("off".equals(f.wrapper)) {
            wrapper = false;
        } else {
            System.err.println("loop: --wrapper must be on | off, got \"" + f.wrapper + "\"");
            return new Parsed(null, 2);
        }
        if (!f.profile.isEmpty()) {
            Shape surface = profileSurface(f.profile);
            if (surface == null) {
                return new Parsed(null, 2);
            }
            shape = narrowShape(shape, surface);
        }
        if (f.keyBits != 0 && f.keyBits != 512 && f.keyBits != 1024 && f.keyBits != 2048) {
            System.err.println("loop: --key-bits must be 512 | 1024 | 2048 (or 0 = profile"
                    + " default), got " + f.keyBits);
            return new Parsed(null, 2);
        }
        if (f.nonceBits != 0 && f.nonceBits != 128 && f.nonceBits != 256 && f.nonceBits != 512) {
            System.err.println("loop: --nonce-bits must be 128 | 256 | 512 (or 0 = profile"
                    + " default), got " + f.nonceBits);
            return new Parsed(null, 2);
        }
        if (f.barrierFill != 0 && f.barrierFill != 1 && f.barrierFill != 2 && f.barrierFill != 4
                && f.barrierFill != 8 && f.barrierFill != 16 && f.barrierFill != 32) {
            System.err.println("loop: --barrier-fill must be 1 | 2 | 4 | 8 | 16 | 32 (or 0 ="
                    + " profile default), got " + f.barrierFill);
            return new Parsed(null, 2);
        }
        Long chunkSize = Size.parseSize(f.chunkSize);
        if (chunkSize == null) {
            System.err.println("loop: --chunk-size: invalid size \"" + f.chunkSize + "\"");
            return new Parsed(null, 2);
        }
        if (f.gomaxprocs < 0) {
            System.err.println(
                    "loop: --gomaxprocs must be > 0 when specified, got " + f.gomaxprocs);
            return new Parsed(null, 2);
        }
        if (f.rekeyEvery < 0) {
            System.err.println("loop: --rekey-every must be >= 0, got " + f.rekeyEvery);
            return new Parsed(null, 2);
        }
        if (f.blobCycleEvery < 0) {
            System.err.println("loop: --blob-cycle-every must be >= 0, got " + f.blobCycleEvery);
            return new Parsed(null, 2);
        }
        PayloadMode payloadMode = Payload.parse(f.payloadMode);
        if (payloadMode == null) {
            System.err.println("loop: --payload-mode must be fixed | rotating | pattern-zero |"
                    + " pattern-ff | pattern-ascii, got \"" + f.payloadMode + "\"");
            return new Parsed(null, 2);
        }
        Config cfg = new Config();
        cfg.durationNs = durationNs;
        cfg.iterations = f.iterations;
        cfg.workersRequested = workers;
        cfg.workers = workers;
        cfg.shape = shape;
        cfg.hash = f.hash;
        cfg.mac = f.mac;
        cfg.payload = payload;
        cfg.memlimit = memlimit;
        cfg.memlimitAuto = memlimitAuto;
        cfg.gogc = (int) f.gogc;
        cfg.parallax = parallax;
        cfg.wrapper = wrapper;
        cfg.profile = f.profile;
        cfg.keyBits = f.keyBits;
        cfg.nonceBits = f.nonceBits;
        cfg.chunkSize = chunkSize;
        cfg.barrierFill = f.barrierFill;
        cfg.gomaxprocs = (int) f.gomaxprocs;
        cfg.rekeyEvery = f.rekeyEvery;
        cfg.blobCycleEvery = f.blobCycleEvery;
        cfg.payloadMode = payloadMode;
        cfg.seed = f.seed;
        cfg.jsonOutput = f.jsonOutput;
        cfg.memprofile = f.memprofile;
        return new Parsed(cfg, 0);
    }

    // ------------------------------------------------------------------
    // Signals
    // ------------------------------------------------------------------

    private static volatile boolean signalSeen;

    /** Counted down once the summary has been emitted, so the shutdown
     * hook can hold the JVM's own termination back until then. */
    private static final CountDownLatch SUMMARY_DONE = new CountDownLatch(1);

    /**
     * Graceful stop. SIGINT / SIGTERM set a flag the main thread polls
     * while it waits for the workers; it turns the flag into the stop
     * request every worker checks before starting an iteration, so a
     * signal interrupts nothing mid-call — the in-flight encrypt /
     * decrypt / compare completes, the worker returns, and the partial
     * summary prints with the verdict the completed iterations earned.
     * Java-specific: the supported way to observe a termination signal
     * is a shutdown hook, which runs concurrently with the main thread
     * rather than in place of it and cannot set the exit code, so the
     * hook only raises the flag and then blocks until the summary is
     * out; the verdict's code is then delivered by halting the runtime
     * from the main thread, which is also what makes the exit code the
     * verdict's rather than the JVM's own signal code.
     */
    private static void installSignals() {
        Thread hook = new Thread(() -> {
            signalSeen = true;
            try {
                SUMMARY_DONE.await(2, TimeUnit.MINUTES);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }, "loop-signal");
        java.lang.Runtime.getRuntime().addShutdownHook(hook);
    }

    // ------------------------------------------------------------------
    // Pipelines
    // ------------------------------------------------------------------

    /** Opts plus whether a keystream layer was filled into them. */
    private static final class Filled {
        final Opts opts;
        final boolean filled;

        Filled(Opts opts, boolean filled) {
            this.opts = opts;
            this.filled = filled;
        }
    }

    /**
     * Supplies the keystream-capable primitive for every layer the
     * profile record leaves unnamed and the run engages: a missing
     * parallax palette becomes three copies of the fill cipher (with the
     * library's default segment size when the record carries none), a
     * missing outer cipher becomes the fill cipher. These are opts
     * overrides that fold into the resolved record the blob carries — a
     * derived profile is never registered, so no name the receiver did
     * not agree to reaches the wire. Null after printing the validation
     * message.
     */
    private static Filled fillKeystreamLayers(String name, Opts opts, boolean wantParallax,
            boolean wantWrapper) {
        Profile p;
        try {
            p = Pipeline.lookup(name);
        } catch (RuntimeException e) {
            System.err.println(
                    "loop: --profile \"" + name + "\" is not a registered triple profile");
            return null;
        }
        boolean filled = false;
        Opts out = opts;
        if (wantParallax && p.palette().isEmpty()) {
            out = out.withParallaxPalette(
                    KEYSTREAM_FILL_CIPHER, KEYSTREAM_FILL_CIPHER, KEYSTREAM_FILL_CIPHER);
            if (p.segment() == 0) {
                // A recipe that never carried a palette never carried a
                // segment size either, and the schedule rejects zero.
                out = out.withParallaxSegmentSize(KEYSTREAM_FILL_SEGMENT);
            }
            filled = true;
        }
        if (wantWrapper && p.outer().isEmpty()) {
            out = out.withOuterCipher(KEYSTREAM_FILL_CIPHER);
            filled = true;
        }
        return new Filled(out, filled);
    }

    /** A constructed Pipeline and the blob it handed out. */
    private static final class Built {
        final Pipeline pipe;
        final byte[] blob;

        Built(Pipeline pipe, byte[] blob) {
            this.pipe = pipe;
            this.blob = blob;
        }
    }

    /**
     * Constructs one Pipeline against profile with every flag-carried
     * override in the opts string (zero values included — the shared
     * library treats zero as "profile default"), then obtains the Init
     * blob once through save: the binding's init entry does not hand the
     * blob back, and the bytes are the ones Init produced. Later blob
     * reopens use the retained blob; save is never called again.
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
                .withChunkSize(cfg.chunkSize);
        if (!cfg.profile.isEmpty()) {
            Filled filled = fillKeystreamLayers(cfg.profile, opts, cfg.parallax, cfg.wrapper);
            if (filled == null) {
                return null;
            }
            opts = filled.opts;
            if (filled.filled) {
                System.err.println("loop: " + cfg.profile
                        + " leaves the requested keystream layers unnamed; "
                        + KEYSTREAM_FILL_CIPHER + " supplied for them");
            }
        }
        Pipeline pipe;
        try {
            pipe = Pipeline.init(profile, opts);
        } catch (RuntimeException e) {
            System.err.println("loop: Init(" + profile + "): " + Worker.detail(e));
            return null;
        }
        byte[] blob;
        try {
            blob = pipe.save();
        } catch (RuntimeException e) {
            System.err.println("loop: Save(" + profile + "): " + Worker.detail(e));
            pipe.close();
            return null;
        }
        logPipelineInitialised(profile, blob);
        return new Built(pipe, blob);
    }

    private static String dash(String s) {
        return s.isEmpty() ? "-" : s;
    }

    /** Prints the construction line with the recipe read back from the
     * blob the Pipeline handed out, not echoed from the flags: every
     * construction override is proven to have reached the library by the
     * value the receiver would see. Record values that are empty (a No
     * MAC profile's MAC, a mixed profile's single hash) print as "-". */
    private static void logPipelineInitialised(String profile, byte[] blob) {
        Profile rec;
        try {
            rec = Pipeline.inspect(blob);
        } catch (RuntimeException e) {
            logLine("pipeline initialised: profile=" + profile + " blob=" + blob.length
                    + " bytes (inspect: " + Worker.detail(e) + ")");
            return;
        }
        logLine("pipeline initialised: profile=" + profile + " blob=" + blob.length + " bytes"
                + " hash=" + dash(rec.hash())
                + " key-bits=" + rec.keyBits()
                + " nonce-bits=" + (rec.nonceBits() == null ? 0 : rec.nonceBits())
                + " barrier-fill=" + (rec.barrierFill() == null ? 0 : rec.barrierFill())
                + " chunk-size=" + rec.chunk()
                + " mac=" + dash(rec.mac())
                + " parallax=" + onOff(rec.parallax())
                + " wrapper=" + onOff(rec.wrapper()));
    }

    // ------------------------------------------------------------------
    // Run
    // ------------------------------------------------------------------

    private static int run(String[] args) {
        Parsed parsed = parseFlags(args);
        Config cfg = parsed.cfg;
        if (cfg == null) {
            return parsed.code;
        }

        // Runtime shaping. A long run under allocation churn grows the
        // Go heap inside the shared library without bound unless a soft
        // limit paces the collector, so a limit is always in force: an
        // explicit --memlimit is set as given, and auto caps the heap
        // only when the runtime reports no limit at all (a limit already
        // installed from the environment is left standing). The GC
        // percentage and GOMAXPROCS are set only when their flag is
        // non-zero — a zero flag skips the setter rather than calling it
        // with zero, because zero is a real value to the GC-percent
        // setter, and a call would clobber whatever the environment
        // installed. All of it lands before any Pipeline exists so the
        // baselines are taken under the shaped runtime.
        if (cfg.memlimitAuto) {
            if (Runtime.setMemoryLimit(-1) == Long.MAX_VALUE) {
                Runtime.setMemoryLimit(cfg.memlimit);
            }
        } else {
            Runtime.setMemoryLimit(cfg.memlimit);
        }
        cfg.memlimit = Runtime.setMemoryLimit(-1);
        if (cfg.gogc > 0) {
            Runtime.setGCPercent(cfg.gogc);
        }
        if (cfg.gomaxprocs > 0) {
            Runtime.setGOMAXPROCS(cfg.gomaxprocs);
        }

        logLine("start: duration=" + Size.humanDuration(cfg.durationNs)
                + " iterations=" + cfg.iterations
                + " goroutines=" + cfg.workersRequested
                + " workers=" + cfg.workers
                + " concurrency=" + CONCURRENCY
                + " shape=" + cfg.shape.label()
                + " hash=" + cfg.hash
                + " mac=" + cfg.mac
                + " payload=" + Size.humanBytes(cfg.payload)
                + " memlimit=" + Size.humanBytes(cfg.memlimit)
                + " parallax=" + onOff(cfg.parallax)
                + " wrapper=" + onOff(cfg.wrapper));
        logLine("overrides: profile=\"" + cfg.profile + "\""
                + " key-bits=" + cfg.keyBits
                + " nonce-bits=" + cfg.nonceBits
                + " chunk-size=" + Size.humanBytes(cfg.chunkSize)
                + " barrier-fill=" + cfg.barrierFill
                + " gomaxprocs=" + cfg.gomaxprocs
                + " rekey-every=" + cfg.rekeyEvery
                + " blob-cycle-every=" + cfg.blobCycleEvery
                + " payload-mode=" + cfg.payloadMode.label()
                + " seed=" + Long.toUnsignedString(cfg.seed)
                + " json-output=" + (cfg.jsonOutput ? "true" : "false"));
        logLine("policy: microbatch-tiers=" + policyLabel("ITB_MICROBATCH_TIERS")
                + " hashpool-starters=" + policyLabel("ITB_HASHPOOL_STARTERS"));

        // Pipeline construction — one shared handle per exercised shape.
        // stream and stream_one_shot share the streaming handle.
        String streamProfile = cfg.profile.isEmpty() ? DEFAULT_STREAM_PROFILE : cfg.profile;
        String msgProfile = cfg.profile.isEmpty() ? DEFAULT_MESSAGE_PROFILE : cfg.profile;
        Pipes pipes = new Pipes();
        if (cfg.shape == Shape.STREAM || cfg.shape == Shape.STREAM_ONE_SHOT
                || cfg.shape == Shape.BOTH) {
            Built built = buildPipeline(cfg, streamProfile);
            if (built == null) {
                return 1;
            }
            pipes.stream = built.pipe;
            pipes.streamBlob = built.blob;
        }
        if (cfg.shape == Shape.MESSAGE || cfg.shape == Shape.BOTH) {
            Built built = buildPipeline(cfg, msgProfile);
            if (built == null) {
                return 1;
            }
            pipes.msg = built.pipe;
            pipes.msgBlob = built.blob;
        }

        // Allocation posture. Per-worker plaintexts are allocated once
        // and held for the whole run (rotating mode refills them in
        // place per iteration); the pump accumulators and the drain
        // scratch live inside each worker and are reused across
        // iterations; the message and one-shot outputs are allocated by
        // the binding per call and reclaimed per iteration. Under the
        // default fixed CSPRNG mode every worker's buffer is distinct,
        // so cross-worker data crossover is detectable; pattern modes
        // trade that property for content edge-case coverage.
        if (cfg.payload > Integer.MAX_VALUE - 8) {
            System.err.println("loop: --payload-size exceeds the largest Java array");
            return 1;
        }
        List<WorkerState> states = new ArrayList<>(cfg.workers);
        for (int id = 0; id < cfg.workers; id++) {
            WorkerState w = new WorkerState();
            w.id = id;
            w.plaintext = new byte[(int) cfg.payload];
            w.payloadMode = cfg.payloadMode;
            w.seeded = cfg.seed != 0;
            w.rng = new Payload.Rng(Payload.seedWorker(cfg.seed, id));
            w.scratch = new byte[PUMP_SLICE];
            if (!Payload.fill(cfg.payloadMode, w.seeded, w.rng, w.plaintext)) {
                System.err.println("loop: payload fill: csprng");
                return 1;
            }
            states.add(w);
        }

        installSignals();
        RunState r = new RunState();
        r.cfg = cfg;
        r.streamProfile = streamProfile;
        r.msgProfile = msgProfile;
        r.pipes = pipes;
        r.workers = new Counters[cfg.workers];
        for (int i = 0; i < cfg.workers; i++) {
            r.workers[i] = new Counters();
        }
        r.warmupDone = new CyclicBarrier(cfg.workers + 1);
        r.release = new CyclicBarrier(cfg.workers + 1);
        r.active = cfg.workers;

        // Warmup barrier. Every worker runs one iteration and waits; the
        // clock starts only once all of them have paid their first-call
        // costs (pool warm-up, lazy kernel dispatch, page faults on the
        // payload buffers, and on this runtime the tiered JIT's first
        // pass over the iteration body), and the RSS and pool baselines
        // taken here describe a process that has already run the whole
        // cipher path once per worker.
        long warmupStart = System.nanoTime();
        List<Thread> threads = new ArrayList<>(cfg.workers);
        for (WorkerState w : states) {
            Thread t = new Thread(() -> Worker.run(r, w), "loop-worker-" + w.id);
            t.setDaemon(false);
            threads.add(t);
            t.start();
        }
        try {
            r.warmupDone.await();
        } catch (InterruptedException | BrokenBarrierException e) {
            Thread.currentThread().interrupt();
            System.err.println("loop: warmup barrier: " + e);
            return 1;
        }
        long[] rss = Summary.readRss();
        long rssWarmup = rss[0];
        long[] poolWarmup = Summary.poolSnapshot();
        logLine("warmup: " + cfg.workers + " workers x 1 iter completed in "
                + Size.humanDuration(Size.roundTo(System.nanoTime() - warmupStart, 100_000_000L))
                + " (baseline rss=" + Size.humanBytes(rssWarmup) + ")");

        // Open the gate; the duration is a deadline the waiter below
        // enforces in duration mode.
        long start = System.nanoTime();
        try {
            r.release.await();
        } catch (InterruptedException | BrokenBarrierException e) {
            Thread.currentThread().interrupt();
            System.err.println("loop: release barrier: " + e);
            return 1;
        }

        // Wait for every worker, polling every 100 ms so the deadline
        // and a signal are both noticed promptly.
        long finish = start;
        synchronized (r.doneLock) {
            while (r.active > 0) {
                if (signalSeen || (cfg.iterations == 0 && System.nanoTime() - start
                        >= cfg.durationNs)) {
                    r.stop = true;
                }
                try {
                    r.doneLock.wait(100);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    r.stop = true;
                }
            }
            if (r.finishNanos != 0) {
                finish = r.finishNanos;
            }
        }
        long elapsedNs = finish - start;
        long[] rssEnd = Summary.readRss();
        long[] poolSteady = Summary.poolSnapshot();
        for (Thread t : threads) {
            try {
                t.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        r.rssWarmup = rssWarmup;
        r.rssFinal = rssEnd[0];
        r.rssPeak = rssEnd[1];
        r.poolWarmup = poolWarmup;
        r.poolSteady = poolSteady;

        if (!cfg.memprofile.isEmpty()) {
            try {
                Runtime.writeHeapProfile(cfg.memprofile);
                logLine("memprofile: heap profile written to " + cfg.memprofile);
            } catch (ItbException e) {
                System.err.println("loop: memprofile: " + Worker.detail(e));
            }
        }

        int exit = Summary.emit(r, elapsedNs);
        if (r.pipes.stream != null) {
            r.pipes.stream.close();
        }
        if (r.pipes.msg != null) {
            r.pipes.msg.close();
        }
        return exit;
    }

    /** Entry point. */
    public static void main(String[] args) {
        int code = run(args);
        System.out.flush();
        System.err.flush();
        SUMMARY_DONE.countDown();
        // Java-specific. The verdict's code is delivered by halting the
        // runtime rather than by returning from main: when a signal has
        // started the shutdown sequence, returning would let the JVM
        // finish that sequence with its own signal-derived code instead
        // of this one.
        java.lang.Runtime.getRuntime().halt(code);
    }
}
