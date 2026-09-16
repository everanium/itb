<?php

declare(strict_types=1);

namespace Everanium\Itb3;

/**
 * Status codes mirrored from the libitb3 C ABI
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

    private function __construct()
    {
    }
}
