<?php

declare(strict_types=1);

namespace Everanium\Itb\Tests;

use Everanium\Itb\Itb;
use PHPUnit\Framework\TestCase;

/**
 * Incremental stream session round trips on the Streaming Non-AEAD
 * profile: whole-buffer, chunked writes with interleaved reads, and
 * the one-shot stream calls.
 */
final class StreamTest extends TestCase
{
    private const PROFILE = 'streaming-noaead-triple-v1';

    public function testStreamSessionRoundTrip(): void
    {
        $plain = \random_bytes(300000);
        $sender = Itb::create(self::PROFILE);
        $receiver = Itb::load($sender->save());

        $enc = $sender->encryptStream();
        $enc->write($plain);
        $wire = $enc->drainAll();
        $this->assertTrue($enc->isFinished());
        $this->assertNotSame('', $wire);
        $enc->free();

        $dec = $receiver->decryptStream();
        $dec->write($wire);
        $back = $dec->drainAll();
        $this->assertTrue($dec->isFinished());
        $this->assertSame($plain, $back);
        $dec->free();

        $sender->free();
        $receiver->free();
    }

    public function testChunkedWritesWithInterleavedReads(): void
    {
        $plain = \random_bytes(500000);
        $sender = Itb::create(self::PROFILE);
        $receiver = Itb::load($sender->save());

        $enc = $sender->encryptStream();
        $wire = '';
        foreach (\str_split($plain, 70001) as $piece) {
            $enc->write($piece);
            // Drain whatever the chain has produced so far; a read
            // before end() never blocks.
            for (;;) {
                $chunk = $enc->read();
                if ($chunk === '') {
                    break;
                }
                $wire .= $chunk;
            }
        }
        $wire .= $enc->drainAll();
        $enc->free();

        $dec = $receiver->decryptStream();
        $back = '';
        foreach (\str_split($wire, 12345) as $piece) {
            $dec->write($piece);
            for (;;) {
                $chunk = $dec->read();
                if ($chunk === '') {
                    break;
                }
                $back .= $chunk;
            }
        }
        $back .= $dec->drainAll();
        $dec->free();

        $this->assertSame($plain, $back);
        $sender->free();
        $receiver->free();
    }

    public function testOneShotStreamRoundTrip(): void
    {
        $plain = \random_bytes(65536);
        $sender = Itb::create(self::PROFILE);
        $receiver = Itb::load($sender->save());
        $wire = $sender->encryptStreamOneShot($plain);
        $this->assertSame($plain, $receiver->decryptStreamOneShot($wire));
        $sender->free();
        $receiver->free();
    }

    public function testSessionSurvivesParentGoingOutOfLocalScope(): void
    {
        // The session pins its parent Pipeline; dropping the caller's
        // only reference must not free the Go-side pipe handle while
        // the session is live.
        $receiverBlob = null;
        $enc = (static function () use (&$receiverBlob) {
            $sender = Itb::create(self::PROFILE);
            $receiverBlob = $sender->save();
            return $sender->encryptStream();
        })();
        \gc_collect_cycles();

        $plain = \random_bytes(100000);
        $enc->write($plain);
        $wire = $enc->drainAll();
        $enc->free();

        $receiver = Itb::load($receiverBlob);
        $dec = $receiver->decryptStream();
        $dec->write($wire);
        $this->assertSame($plain, $dec->drainAll());
        $dec->free();
        $receiver->free();
    }
}
