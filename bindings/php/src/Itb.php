<?php

declare(strict_types=1);

namespace Everanium\Itb;

/**
 * Static facade over the libitb Triple Pipeline surface.
 *
 * Every hash-name / MAC-name / cipher-name / profile-name is an
 * opaque string passed through to Go for validation; the binding
 * carries no ITB construction logic of its own. Opts are supplied as
 * a PHP array of key => value pairs (booleans render as
 * "true" / "false", everything else via string cast) and cross the
 * FFI boundary as the URL-query-encoded string libitb parses.
 *
 * Example:
 *
 *     use Everanium\Itb\Itb;
 *
 *     $sender = Itb::create('singlemsg-triple-mac-v1');
 *     $receiver = Itb::open('singlemsg-triple-mac-v1', $sender->blob());
 *     $wire = $sender->encryptMessage('hello');
 *     assert($receiver->decryptMessage($wire) === 'hello');
 */
final class Itb
{
    /** Binding version. */
    public const VERSION = '0.3.1';

    /** Floor capacity for blob output buffers (create / rekey). */
    public const BLOB_CAP = 65536;

    /**
     * Shipped profile identifiers, mirrored from the Go triple
     * package registry in declaration order. The C ABI exposes no
     * profile enumeration, so the roster is pinned here; profiles
     * registered at runtime via registerProfile() are not included.
     */
    private const PROFILES = [
        'streaming-aead-triple-mac-v1',
        'streaming-noaead-triple-v1',
        'singlemsg-triple-mac-v1',
        'singlemsg-triple-nomac-v1',
        'blob-triple-mac-v1',
        'streaming-aead-triple-mac-mixed-v1',
        'streaming-noaead-triple-mixed-v1',
        'singlemsg-triple-mac-mixed-v1',
        'singlemsg-triple-nomac-mixed-v1',
    ];

    /**
     * Constructs a fresh Pipeline against the named profile. On a
     * blob-buffer retry the Init re-runs and yields a fresh session
     * (the undersized attempt is closed by libitb before returning).
     *
     * @param array<string, bool|int|float|string> $opts
     */
    public static function create(string $profile, array $opts = []): Pipeline
    {
        $ffi = FFIBridge::get();
        $optsStr = self::buildOpts($opts);
        $handle = $ffi->new('uintptr_t');
        $handlePtr = \FFI::addr($handle);

        $blob = FFIBridge::retryOnce(
            self::BLOB_CAP,
            static function ($buf, int $cap, $lenPtr) use ($ffi, $profile, $optsStr, $handlePtr): int {
                return $ffi->ITB_Triple_Init($profile, $optsStr, $buf, $cap, $lenPtr, $handlePtr);
            }
        );
        return new Pipeline((int) $handle->cdata, $blob);
    }

    /**
     * Reconstructs a Pipeline from a blob produced by create() or
     * Pipeline::rekey(). $masters is null to use the blob-embedded
     * masters, or a [perm, wrap] pair of non-empty byte-strings to
     * override them.
     *
     * @param array<string, bool|int|float|string> $opts
     * @param array{0: string, 1: string}|null     $masters
     */
    public static function open(string $profile, string $blob, array $opts = [], ?array $masters = null): Pipeline
    {
        $ffi = FFIBridge::get();
        $optsStr = self::buildOpts($opts);
        if ($masters === null) {
            $pm = '';
            $wm = '';
            $count = 0;
        } else {
            $pm = $masters[0];
            $wm = $masters[1];
            if ($pm === '' || $wm === '') {
                throw new ItbException('master override buffers must be non-empty');
            }
            $count = 2;
        }
        $handle = $ffi->new('uintptr_t');
        FFIBridge::check($ffi->ITB_Triple_Open(
            $profile,
            $blob,
            \strlen($blob),
            $optsStr,
            $pm,
            \strlen($pm),
            $wm,
            \strlen($wm),
            $count,
            \FFI::addr($handle)
        ));
        return new Pipeline((int) $handle->cdata, $blob);
    }

    /**
     * Registers a user-defined Triple profile under $name so
     * subsequent create() / open() calls resolve it. The opts follow
     * the register-profile grammar validated by Go (mode, width,
     * innerHash / innerHashes, keyBits, macName, outerCipher,
     * parallaxPalette, parallaxSegmentSize, chunkSize, parallaxOn,
     * wrapperOn). A duplicate name fails with Status::PROFILE_EXISTS.
     *
     * @param array<string, bool|int|float|string> $opts
     */
    public static function registerProfile(string $name, array $opts): void
    {
        $ffi = FFIBridge::get();
        FFIBridge::check($ffi->ITB_Triple_RegisterProfile($name, self::buildOpts($opts)));
    }

    /**
     * The shipped hash primitive roster as name => width-bits pairs
     * in canonical registry order.
     *
     * @return array<string, int>
     */
    public static function hashes(): array
    {
        $ffi = FFIBridge::get();
        $out = [];
        $count = $ffi->ITB_HashCount();
        $buf = $ffi->new('char[128]');
        $n = $ffi->new('size_t');
        for ($i = 0; $i < $count; $i++) {
            FFIBridge::check($ffi->ITB_HashName($i, $buf, 128, \FFI::addr($n)));
            $name = \FFI::string($buf, max((int) $n->cdata - 1, 0));
            $out[$name] = $ffi->ITB_HashWidth($i);
        }
        return $out;
    }

    /**
     * The shipped profile identifiers in Go registry declaration
     * order.
     *
     * @return list<string>
     */
    public static function profiles(): array
    {
        return self::PROFILES;
    }

    /** The libitb library version string. */
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
     * The Go-side diagnostic recorded by the most recent failing
     * libitb call (process-global last-write-wins; '' when none).
     * The exceptions already carry this detail — direct use is for
     * ad-hoc debugging only.
     */
    public static function lastError(): string
    {
        return FFIBridge::lastError();
    }

    /**
     * Renders an opts array as the URL-query string libitb parses.
     * No validation happens binding-side; libitb rejects unknown
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

    private function __construct()
    {
    }
}
