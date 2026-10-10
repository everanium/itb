<?php

declare(strict_types=1);

namespace Everanium\Itb3;

/**
 * Static facade over the libitb3 Triple Pipeline surface.
 *
 * Every hash-name / MAC-name / cipher-name / profile-name is an
 * opaque string passed through to Go for validation; the binding
 * carries no ITB construction logic of its own. Opts are supplied as
 * a PHP array of key => value pairs (booleans render as
 * "true" / "false", everything else via string cast) and cross the
 * FFI boundary as the URL-query-encoded string libitb3 parses.
 *
 * Example:
 *
 *     use Everanium\Itb3\Itb;
 *
 *     $sender = Itb::create('singlemsg-triple-mac-v1');
 *     $receiver = Itb::load($sender->save());
 *     $wire = $sender->encryptMessage('hello');
 *     assert($receiver->decryptMessage($wire) === 'hello');
 */
final class Itb
{
    /** Binding version. */
    public const VERSION = '0.5.5';

    /** Floor capacity for blob output buffers (create / save / rekey). */
    public const BLOB_CAP = 65536;

    /** Floor capacity for profile-JSON output buffers (inspect / lookup / profiles). */
    public const JSON_CAP = 4096;

    /**
     * Constructs a fresh Pipeline against the named profile. The
     * session blob is available through Pipeline::save(). On a
     * blob-buffer retry the Init re-runs and yields a fresh session
     * (the undersized attempt is closed by libitb3 before returning).
     *
     * @param array<string, bool|int|float|string> $opts
     */
    public static function create(string $profile, array $opts = []): Pipeline
    {
        $ffi = FFIBridge::get();
        $optsStr = self::buildOpts($opts);
        $handle = $ffi->new('uintptr_t');
        $handlePtr = \FFI::addr($handle);

        FFIBridge::retryOnce(
            self::BLOB_CAP,
            static function ($buf, int $cap, $lenPtr) use ($ffi, $profile, $optsStr, $handlePtr): int {
                return $ffi->ITB_Triple_Init($profile, $optsStr, $buf, $cap, $lenPtr, $handlePtr);
            }
        );
        return new Pipeline((int) $handle->cdata);
    }

    /**
     * Reconstructs a Pipeline from a blob produced by
     * Pipeline::save() or Pipeline::rekey(). The blob's embedded
     * profile record is the sole structural source — no profile
     * name, no opts. $masters is null to use the blob-embedded
     * masters, or a [perm, wrap] pair of byte-strings to override
     * them.
     *
     * @param array{0: string, 1: string}|null $masters
     */
    public static function load(string $blob, ?array $masters = null): Pipeline
    {
        $ffi = FFIBridge::get();
        [$pm, $wm, $count] = self::masters($masters);
        $handle = $ffi->new('uintptr_t');
        FFIBridge::check($ffi->ITB_Triple_Load(
            $blob,
            \strlen($blob),
            $pm,
            \strlen($pm),
            $wm,
            \strlen($wm),
            $count,
            \FFI::addr($handle)
        ));
        return new Pipeline((int) $handle->cdata);
    }

    /**
     * load() for a blob stored in a file; the file is read inside
     * the library.
     *
     * @param array{0: string, 1: string}|null $masters
     */
    public static function loadF(string $path, ?array $masters = null): Pipeline
    {
        $ffi = FFIBridge::get();
        [$pm, $wm, $count] = self::masters($masters);
        $handle = $ffi->new('uintptr_t');
        FFIBridge::check($ffi->ITB_Triple_LoadF(
            $path,
            $pm,
            \strlen($pm),
            $wm,
            \strlen($wm),
            $count,
            \FFI::addr($handle)
        ));
        return new Pipeline((int) $handle->cdata);
    }

    /**
     * Decodes the blob's embedded profile record without opening a
     * Pipeline and returns it as an associative array decoded from
     * the JSON libitb3 emits; absent keys are optional fields at their
     * zero value. No registry read, no primitive probe.
     *
     * @return array<string, mixed>
     */
    public static function inspect(string $blob): array
    {
        $ffi = FFIBridge::get();
        return self::jsonOut(static function ($buf, int $cap, $lenPtr) use ($ffi, $blob): int {
            return $ffi->ITB_Triple_Inspect($blob, \strlen($blob), $buf, $cap, $lenPtr);
        });
    }

    /**
     * Registers a profile record under $name so subsequent create()
     * / lookup() calls resolve it. $profile is the record as an
     * associative array (the shape inspect() / lookup() return) or an
     * already-encoded JSON string; a "name" key inside it, if
     * present, must be empty or equal to $name. Validation (name
     * pattern, reserved prefixes, field rules) is performed by
     * libitb3; a duplicate name fails with Status::PROFILE_EXISTS.
     *
     * @param array<string, mixed>|string $profile
     */
    public static function register(string $name, $profile): void
    {
        $text = \is_string($profile) ? $profile : \json_encode($profile, \JSON_THROW_ON_ERROR);
        FFIBridge::check(FFIBridge::get()->ITB_Triple_Register($name, $text));
    }

    /**
     * The profile record registered under $name (a shipped catalogue
     * entry or a prior register()) as an associative array. An
     * unknown name throws ItbException with Status::UNKNOWN_PROFILE.
     *
     * @return array<string, mixed>
     */
    public static function lookup(string $name): array
    {
        $ffi = FFIBridge::get();
        return self::jsonOut(static function ($buf, int $cap, $lenPtr) use ($ffi, $name): int {
            return $ffi->ITB_Triple_Lookup($name, $buf, $cap, $lenPtr);
        });
    }

    /**
     * The sorted list of every registered profile name.
     *
     * @return list<string>
     */
    public static function profiles(): array
    {
        $ffi = FFIBridge::get();
        return self::jsonOut(static function ($buf, int $cap, $lenPtr) use ($ffi): int {
            return $ffi->ITB_Triple_Profiles($buf, $cap, $lenPtr);
        });
    }

    /**
     * The shipped inner-hash registry as a list of primitive names, in
     * registry order. Runtime-registered custom primitives are not part
     * of this enumeration.
     *
     * @return list<string>
     */
    public static function hashNames(): array
    {
        $ffi = FFIBridge::get();
        return self::jsonOut(static function ($buf, int $cap, $lenPtr) use ($ffi): int {
            return $ffi->ITB_Triple_HashNames($buf, $cap, $lenPtr);
        });
    }

    /** The libitb3 library version string. */
    public static function version(): string
    {
        $ffi = FFIBridge::get();
        $need = $ffi->new('size_t');
        $rc = $ffi->ITB_Version(null, 0, \FFI::addr($need));
        if ($rc !== Status::OK && $rc !== Status::BUFFER_TOO_SMALL) {
            throw new ItbException(FFIBridge::lastError(), $rc);
        }
        $needed = (int) $need->cdata;
        if ($needed <= 1) {
            return '';
        }
        $buf = $ffi->new("char[$needed]");
        FFIBridge::check($ffi->ITB_Version($buf, $needed, \FFI::addr($need)));
        return \FFI::string($buf, max((int) $need->cdata - 1, 0));
    }

    /**
     * The fill cipher the auto DRBG tier selected on this host
     * ("aes-256-ctr" or "chacha20"): the tier a Pipeline uses when its
     * drbg option is empty, resolved per host and recorded in no blob.
     */
    public static function drbgAutoTier(): string
    {
        $ffi = FFIBridge::get();
        $need = $ffi->new('size_t');
        $rc = $ffi->ITB_DRBGAutoTier(null, 0, \FFI::addr($need));
        if ($rc !== Status::OK && $rc !== Status::BUFFER_TOO_SMALL) {
            throw new ItbException(FFIBridge::lastError(), $rc);
        }
        $needed = (int) $need->cdata;
        if ($needed <= 1) {
            return '';
        }
        $buf = $ffi->new("char[$needed]");
        FFIBridge::check($ffi->ITB_DRBGAutoTier($buf, $needed, \FFI::addr($need)));
        return \FFI::string($buf, max((int) $need->cdata - 1, 0));
    }

    /**
     * Sets the Go runtime's soft heap limit in bytes and returns the
     * previous limit. A negative value queries without changing.
     */
    public static function setMemoryLimit(int $limitBytes): int
    {
        return (int) FFIBridge::get()->ITB_SetMemoryLimit($limitBytes);
    }

    /**
     * Sets the Go GC trigger percentage and returns the previous
     * value. A negative value queries without changing.
     */
    public static function setGcPercent(int $pct): int
    {
        return (int) FFIBridge::get()->ITB_SetGCPercent($pct);
    }

    /**
     * Sets the Go runtime's GOMAXPROCS — the number of OS threads
     * executing Go code simultaneously inside the library — and returns
     * the previous value. $n <= 0 queries without changing.
     */
    public static function setGomaxprocs(int $n): int
    {
        return (int) FFIBridge::get()->ITB_SetGOMAXPROCS($n);
    }

    /**
     * Writes a Go runtime heap profile (pprof format, readable with
     * `go tool pprof`) to $path after one forced garbage collection. An
     * empty path falls back to the ITB_MEMPROFILE environment variable;
     * a file-system failure throws ItbException carrying the os
     * diagnostic.
     */
    public static function writeHeapProfile(string $path): void
    {
        FFIBridge::check(FFIBridge::get()->ITB_WriteHeapProfile($path));
    }

    /**
     * The number of int64 slots poolStats() fills. A caller sizes its
     * buffer from this value rather than a constant: the slot count
     * grows if the library adds a pool.
     */
    public static function poolStatsLen(): int
    {
        return (int) FFIBridge::get()->ITB_PoolStatsLen();
    }

    /**
     * The library's pool hit / miss counters, every one a monotonically
     * increasing total since library load (a consumer differences two
     * snapshots).
     *
     * Slot layout, with T the hash-array pool tier count in slot 0: for
     * tier i the five slots at 1 + 5*i hold the starter width (0 for an
     * unused tier), checkouts, constructor misses, regrow replacements
     * and bytes allocated by misses + regrows; the four slots at
     * 1 + 5*T hold the scratch byte pool's get / new / regrow /
     * regrow-bytes and the four after them the parallax chunk pool's,
     * in the same order.
     *
     * @return list<int>
     */
    public static function poolStats(): array
    {
        $ffi = FFIBridge::get();
        // The capacity this entry takes is counted in int64 slots, not
        // in bytes, so the array is declared by element count and the
        // same count is handed over.
        $cap = (int) $ffi->ITB_PoolStatsLen();
        if ($cap <= 0) {
            return [];
        }
        $buf = $ffi->new("int64_t[$cap]");
        $len = $ffi->new('size_t');
        FFIBridge::check($ffi->ITB_PoolStats($buf, $cap, \FFI::addr($len)));
        $n = \min((int) $len->cdata, $cap);
        $out = [];
        for ($i = 0; $i < $n; $i++) {
            $out[] = (int) $buf[$i];
        }
        return $out;
    }

    /**
     * The Go-side diagnostic recorded by the most recent failing
     * libitb3 call (process-global last-write-wins; '' when none).
     * The exceptions already carry this detail — direct use is for
     * ad-hoc debugging only.
     */
    public static function lastError(): string
    {
        return FFIBridge::lastError();
    }

    /**
     * Renders an opts array as the URL-query string libitb3 parses.
     * No validation happens binding-side; libitb3 rejects unknown
     * keys or bad values with a diagnostic surfaced via
     * ItbException. Commas stay literal so palette / constellation
     * lists read naturally in diagnostics.
     *
     * @param array<string, bool|int|float|string> $opts
     */
    private static function buildOpts(array $opts): string
    {
        $pairs = [];
        foreach ($opts as $key => $value) {
            if (\is_bool($value)) {
                $value = $value ? 'true' : 'false';
            }
            $pairs[] = \str_replace('%2C', ',', \rawurlencode((string) $key))
                . '='
                . \str_replace('%2C', ',', \rawurlencode((string) $value));
        }
        return \implode('&', $pairs);
    }

    /**
     * Folds the optional [perm, wrap] master pair into the
     * (perm_master, wrap_master, masters_count) triple the Load
     * entries take: count 0 selects the blob-embedded masters, count
     * 2 overrides them.
     *
     * @param array{0: string, 1: string}|null $masters
     * @return array{0: string, 1: string, 2: int}
     */
    private static function masters(?array $masters): array
    {
        if ($masters === null) {
            return ['', '', 0];
        }
        return [$masters[0], $masters[1], 2];
    }

    /**
     * Shared body for the JSON-returning catalogue entries:
     * retry-once buffer, then a standard-library JSON decode of the
     * bytes libitb3 wrote.
     *
     * @param callable(\FFI\CData, int, \FFI\CData): int $call
     * @return array<mixed>
     */
    private static function jsonOut(callable $call): array
    {
        return \json_decode(FFIBridge::retryOnce(self::JSON_CAP, $call), true, 512, \JSON_THROW_ON_ERROR);
    }

    private function __construct()
    {
    }
}
