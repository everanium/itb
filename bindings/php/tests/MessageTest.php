<?php

declare(strict_types=1);

namespace Everanium\Itb\Tests;

use Everanium\Itb\FFIBridge;
use Everanium\Itb\Itb;
use PHPUnit\Framework\TestCase;

/**
 * Single Message round trips (small / medium / >1 MiB payloads),
 * rekey, and the buffer retry-once path exercised with a deliberately
 * undersized initial capacity.
 */
final class MessageTest extends TestCase
{
    /** Deterministic non-trivial payload (xorshift-style fill). */
    private static function payload(int $n, int $seed): string
    {
        $x = $seed | 1;
        $out = '';
        for ($i = 0; $i < $n; $i += 8) {
            $x ^= ($x << 13) & 0x7FFFFFFFFFFFFFFF;
            $x ^= ($x >> 7) & 0x7FFFFFFFFFFFFFFF;
            $x ^= ($x << 17) & 0x7FFFFFFFFFFFFFFF;
            $out .= \pack('P', $x);
        }
        return \substr($out, 0, $n);
    }

    public function testMessageRoundTrip(): void
    {
        $sender = Itb::create('singlemsg-triple-mac-v1');
        $receiver = Itb::load($sender->save());
        foreach ([1, 4096, 262144] as $size) {
            $plain = self::payload($size, $size + 1);
            $wire = $sender->encryptMessage($plain);
            $this->assertNotSame($plain, $wire);
            $this->assertSame($plain, $receiver->decryptMessage($wire), "size $size");
        }
        $sender->free();
        $receiver->free();
    }

    public function testLargePlaintextRoundTrip(): void
    {
        // >1 MiB payload — exercises the 1.25x + 131072 pre-allocation
        // formula at a size where the fixed floor no longer dominates.
        $size = 2 * 1024 * 1024 + 12345;
        $plain = self::payload($size, 7);
        $sender = Itb::create('singlemsg-triple-nomac-v1');
        $receiver = Itb::load($sender->save());
        $wire = $sender->encryptMessage($plain);
        $this->assertSame($plain, $receiver->decryptMessage($wire));
        $sender->free();
        $receiver->free();
    }

    public function testBufferTooSmallRetryOnce(): void
    {
        // Drives FFIBridge::retryOnce with an 8-byte initial capacity
        // so the first EncryptMessage call must report
        // BUFFER_TOO_SMALL with the exact required size; the single
        // retry then succeeds and the wire decrypts.
        $sender = Itb::create('singlemsg-triple-mac-v1');
        $receiver = Itb::load($sender->save());
        $plain = 'retry-once probe payload';
        $ffi = FFIBridge::get();
        $handle = new \ReflectionProperty($sender, 'handle');
        if (\PHP_VERSION_ID < 80100) {
            $handle->setAccessible(true);
        }
        $h = $handle->getValue($sender);
        $srcLen = \strlen($plain);
        $wire = FFIBridge::retryOnce(
            8,
            static function ($buf, int $cap, $lenPtr) use ($ffi, $h, $plain, $srcLen): int {
                return $ffi->ITB_Triple_EncryptMessage($h, $plain, $srcLen, $buf, $cap, $lenPtr);
            }
        );
        $this->assertGreaterThan(8, \strlen($wire));
        $this->assertSame($plain, $receiver->decryptMessage($wire));
        $sender->free();
        $receiver->free();
    }

    public function testRekeyRefreshesBlobAndRoundTrips(): void
    {
        $sender = Itb::create('singlemsg-triple-mac-v1');
        $before = $sender->save();
        $rotated = $sender->rekey(\str_repeat("\x11", 32), \str_repeat("\x22", 32));
        $this->assertNotSame($before, $rotated, 'rekey must refresh the blob');
        $this->assertSame($rotated, $sender->save(), 'save must observe the rekey');

        $receiver = Itb::load($rotated);
        $plain = 'post-rekey payload';
        $this->assertSame($plain, $receiver->decryptMessage($sender->encryptMessage($plain)));
        $sender->free();
        $receiver->free();
    }
}
