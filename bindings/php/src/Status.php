<?php

declare(strict_types=1);

namespace Everanium\Itb;

/**
 * Status codes mirrored from the libitb C ABI
 * (cmd/cshared/internal/capi/errors.go). Numeric values are stable
 * across releases.
 */
final class Status
{
    public const OK = 0;
    public const BAD_HASH = 1;
    public const BAD_KEY_BITS = 2;
    public const BAD_HANDLE = 3;
    public const BAD_INPUT = 4;
    public const BUFFER_TOO_SMALL = 5;
    public const ENCRYPT_FAILED = 6;
    public const DECRYPT_FAILED = 7;
    public const SEED_WIDTH_MIX = 8;
    public const BAD_MAC = 9;
    public const MAC_FAILURE = 10;
    public const BLOB_MALFORMED_RECIPE = 11;
    public const RECIPE_PRIMITIVE_UNKNOWN = 12;
    public const UNKNOWN_PROFILE = 13;
    public const BLOB_MODE_MISMATCH = 19;
    public const BLOB_MALFORMED = 20;
    public const BLOB_VERSION_TOO_NEW = 21;
    public const BLOB_TOO_MANY_OPTS = 22;
    public const STREAM_TRUNCATED = 23;
    public const STREAM_AFTER_FINAL = 24;
    public const TRIPLE_CLOSED = 25;
    public const PROFILE_EXISTS = 26;
    public const INTERNAL = 99;

    /** @var array<int, string> */
    private const LABELS = [
        self::OK => 'ok',
        self::BAD_HASH => 'unknown hash name',
        self::BAD_KEY_BITS => 'invalid key bits',
        self::BAD_HANDLE => 'invalid handle',
        self::BAD_INPUT => 'invalid input',
        self::BUFFER_TOO_SMALL => 'output buffer too small',
        self::ENCRYPT_FAILED => 'encrypt failed',
        self::DECRYPT_FAILED => 'decrypt failed',
        self::SEED_WIDTH_MIX => 'seed width mismatch',
        self::BAD_MAC => 'unknown MAC name or invalid MAC handle',
        self::MAC_FAILURE => 'MAC verification failed',
        self::BLOB_MALFORMED_RECIPE => 'blob profile record invalid',
        self::RECIPE_PRIMITIVE_UNKNOWN => 'blob profile record names a primitive absent from the local registries',
        self::UNKNOWN_PROFILE => 'unknown profile name',
        self::BLOB_MODE_MISMATCH => 'blob mode mismatch',
        self::BLOB_MALFORMED => 'malformed state blob',
        self::BLOB_VERSION_TOO_NEW => 'blob version too new',
        self::BLOB_TOO_MANY_OPTS => 'too many blob export opts',
        self::STREAM_TRUNCATED => 'stream truncated before terminator',
        self::STREAM_AFTER_FINAL => 'stream chunk after terminator',
        self::TRIPLE_CLOSED => 'Triple Pipeline is closed',
        self::PROFILE_EXISTS => 'profile name already registered',
        self::INTERNAL => 'internal error',
    ];

    /** Short human-readable label for a status code. */
    public static function label(int $code): string
    {
        return self::LABELS[$code] ?? 'unknown status';
    }

    private function __construct()
    {
    }
}
