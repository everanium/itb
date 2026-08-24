<?php

declare(strict_types=1);

namespace Everanium\Itb;

/**
 * Internal singleton loading the libitb shared library through PHP's
 * FFI extension.
 *
 * The library is loaded once per process and never unloaded, so the
 * cached \FFI instance stays valid for the process lifetime. Search
 * order:
 *
 * 1. ITB_LIBITB_PATH environment variable (path to the shared
 *    library file).
 * 2. <repo>/dist/<os>-<arch>/libitb.<ext> resolved from this file
 *    (in-repo builds).
 * 3. The OS default loader path (LD_LIBRARY_PATH, ld.so.cache,
 *    DYLD_LIBRARY_PATH, PATH).
 *
 * A resolve failure surfaces as ItbException at the first FFI call;
 * the failure is cached and re-reported on every subsequent call.
 *
 * @internal Not part of the public binding surface.
 */
final class FFIBridge
{
    /** @var \FFI|null */
    private static $ffi = null;

    /** @var ItbException|null */
    private static $loadError = null;

    /** Returns the process-wide \FFI instance, loading on first use. */
    public static function get(): \FFI
    {
        if (self::$ffi !== null) {
            return self::$ffi;
        }
        if (self::$loadError !== null) {
            throw self::$loadError;
        }
        try {
            self::$ffi = self::load();
        } catch (ItbException $e) {
            self::$loadError = $e;
            throw $e;
        }
        return self::$ffi;
    }

    /** Maps a raw FFI return code onto void / ItbException. */
    public static function check(int $rc): void
    {
        if ($rc === Status::OK) {
            return;
        }
        throw new ItbException(self::lastError(), $rc);
    }

    /**
     * Reads the ITB_LastError diagnostic (NUL-stripped). Returns ''
     * when no diagnostic is recorded or the library is unavailable.
     */
    public static function lastError(): string
    {
        try {
            $ffi = self::get();
        } catch (ItbException $e) {
            return '';
        }
        $need = $ffi->new('size_t');
        $rc = $ffi->ITB_LastError(null, 0, \FFI::addr($need));
        $needed = (int) $need->cdata;
        if (($rc !== Status::OK && $rc !== Status::BUFFER_TOO_SMALL) || $needed <= 1) {
            return '';
        }
        $buf = $ffi->new("char[$needed]");
        $rc = $ffi->ITB_LastError($buf, $needed, \FFI::addr($need));
        if ($rc !== Status::OK) {
            return '';
        }
        return \FFI::string($buf, max((int) $need->cdata - 1, 0));
    }

    /**
     * Single retry-once dispatch site for every variable-size output
     * buffer: pre-allocate $cap bytes, invoke
     * $call($buf, $cap, $lenPtr), and on BUFFER_TOO_SMALL with a
     * reported length strictly exceeding the current capacity retry
     * once with exactly the reported size.
     *
     * @param callable(\FFI\CData, int, \FFI\CData): int $call
     */
    public static function retryOnce(int $cap, callable $call): string
    {
        $ffi = self::get();
        $buf = $ffi->new("char[$cap]");
        $len = $ffi->new('size_t');
        $rc = $call($buf, $cap, \FFI::addr($len));
        // Retry only when the reported length strictly exceeds the
        // current capacity.
        if ($rc === Status::BUFFER_TOO_SMALL && (int) $len->cdata > $cap) {
            $cap = (int) $len->cdata;
            $buf = $ffi->new("char[$cap]");
            $rc = $call($buf, $cap, \FFI::addr($len));
        }
        self::check($rc);
        $n = (int) $len->cdata;
        return $n > 0 ? \FFI::string($buf, $n) : '';
    }

    private static function load(): \FFI
    {
        if (!\extension_loaded('ffi')) {
            throw new ItbException(
                'the FFI extension is not loaded — enable extension=ffi in php.ini '
                . 'or run php with -d extension=ffi -d ffi.enable=1'
            );
        }
        $header = __DIR__ . '/../include/itb.h';
        $decls = @\file_get_contents($header);
        if ($decls === false) {
            throw new ItbException("cannot read FFI declarations: $header");
        }
        $path = self::libraryPath();
        try {
            return \FFI::cdef($decls, $path);
        } catch (\FFI\Exception $e) {
            throw new ItbException("failed to load libitb ($path): " . $e->getMessage());
        } catch (\Throwable $e) {
            throw new ItbException("failed to load libitb ($path): " . $e->getMessage());
        }
    }

    private static function libraryPath(): string
    {
        $env = \getenv('ITB_LIBITB_PATH');
        if (\is_string($env) && $env !== '') {
            return $env;
        }
        // bindings/php/src/FFIBridge.php -> repo root is three levels up.
        $repo = \dirname(__DIR__, 3);
        $cand = $repo . '/dist/' . self::distSubdir() . '/' . self::libFilename();
        if (\is_file($cand)) {
            return $cand;
        }
        return self::libFilename();
    }

    private static function libFilename(): string
    {
        switch (\PHP_OS_FAMILY) {
            case 'Windows':
                return 'libitb.dll';
            case 'Darwin':
                return 'libitb.dylib';
            default:
                return 'libitb.so';
        }
    }

    private static function distSubdir(): string
    {
        switch (\PHP_OS_FAMILY) {
            case 'Windows':
                $os = 'windows';
                break;
            case 'Darwin':
                $os = 'darwin';
                break;
            default:
                $os = 'linux';
        }
        $machine = \strtolower(\php_uname('m'));
        $map = [
            'x86_64' => 'amd64',
            'amd64' => 'amd64',
            'aarch64' => 'arm64',
            'arm64' => 'arm64',
        ];
        $arch = $map[$machine] ?? $machine;
        return "$os-$arch";
    }

    private function __construct()
    {
    }
}
