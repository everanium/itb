<?php

declare(strict_types=1);

namespace Everanium\Itb\Tests;

use Everanium\Itb\Itb;
use Everanium\Itb\ItbException;
use Everanium\Itb\Status;
use PHPUnit\Framework\TestCase;

/**
 * Error-mapping surface: opaque-string relay, closed Pipeline,
 * tampered-wire MAC failure, duplicate profile registration.
 */
final class ErrorsTest extends TestCase
{
    public function testUnknownProfileIsBadInputWithDiagnostic(): void
    {
        try {
            Itb::create('no-such-profile');
            $this->fail('expected ItbException');
        } catch (ItbException $e) {
            $this->assertSame(Status::BAD_INPUT, $e->getStatus());
            $this->assertNotSame('', $e->getMessage());
        }
    }

    public function testUnknownOptsKeyIsBadInput(): void
    {
        try {
            // Typoed key (lowercase s) — Go rejects unknown keys.
            Itb::create('singlemsg-triple-mac-v1', ['chunksize' => 4096]);
            $this->fail('expected ItbException');
        } catch (ItbException $e) {
            $this->assertSame(Status::BAD_INPUT, $e->getStatus());
        }
    }

    public function testOpaquePrimitiveNameRelay(): void
    {
        // An unknown inner-hash name is relayed to Go and rejected
        // there — the binding performs no name validation of its own.
        try {
            Itb::create('singlemsg-triple-mac-v1', ['innerHash' => 'no-such-hash']);
            $this->fail('expected ItbException');
        } catch (ItbException $e) {
            $this->assertNotNull($e->getStatus());
            $this->assertNotSame(Status::OK, $e->getStatus());
        }
    }

    public function testClosedPipelineReportsTripleClosed(): void
    {
        $pipe = Itb::create('singlemsg-triple-mac-v1');
        $pipe->close();
        $pipe->close(); // idempotent
        try {
            $pipe->encryptMessage('payload');
            $this->fail('expected ItbException');
        } catch (ItbException $e) {
            $this->assertSame(Status::TRIPLE_CLOSED, $e->getStatus());
        }
        $pipe->free();
    }

    public function testTamperedWireFailsAuthentication(): void
    {
        // A single bit flip can land in the container's CSPRNG
        // residue — over-sized container area that carries no payload
        // — where the decrypt legitimately completes clean. The test
        // probes successive flip positions until one lands in
        // authenticated content; the observed failure must be MAC
        // failure. The probe is black-box — no wire-layout knowledge
        // is used.
        $sender = Itb::create('singlemsg-triple-mac-v1');
        $receiver = Itb::open('singlemsg-triple-mac-v1', $sender->blob());
        $plain = \random_bytes(65536);
        $wire = $sender->encryptMessage($plain);
        $len = \strlen($wire);

        $seenFailure = false;
        for ($attempt = 0; $attempt < 32 && !$seenFailure; $attempt++) {
            $pos = (\intdiv($len * 3, 4) + $attempt * 1031) % $len;
            $tampered = $wire;
            $tampered[$pos] = \chr(\ord($tampered[$pos]) ^ 0x01);
            try {
                $back = $receiver->decryptMessage($tampered);
                // Flip landed in residue — plaintext must still be
                // intact; try the next position.
                $this->assertSame($plain, $back);
            } catch (ItbException $e) {
                $this->assertSame(
                    Status::MAC_FAILURE,
                    $e->getStatus(),
                    "expected MAC failure at flip position $pos"
                );
                $seenFailure = true;
            }
        }
        $this->assertTrue($seenFailure, 'no flip position produced an authentication failure');
        $sender->free();
        $receiver->free();
    }

    public function testRegisterProfileMixedThenDuplicate(): void
    {
        // 8-entry width-256 innerHashes constellation, layers off.
        $opts = [
            'mode' => 'singlemsg-nomac',
            'width' => 256,
            'innerHashes' => 'blake3,blake2s,areion256,blake2b256,chacha20,blake3,blake2s,areion256',
            'keyBits' => 1024,
            'parallaxOn' => false,
            'wrapperOn' => false,
        ];
        Itb::registerProfile('php-binding-test-mixed', $opts);

        // The registered profile round-trips.
        $sender = Itb::create('php-binding-test-mixed');
        $receiver = Itb::open('php-binding-test-mixed', $sender->blob());
        $wire = $sender->encryptMessage('custom profile');
        $this->assertSame('custom profile', $receiver->decryptMessage($wire));
        $sender->free();
        $receiver->free();

        // Duplicate name is a distinct status.
        try {
            Itb::registerProfile('php-binding-test-mixed', $opts);
            $this->fail('expected ItbException');
        } catch (ItbException $e) {
            $this->assertSame(Status::PROFILE_EXISTS, $e->getStatus());
        }
    }

    public function testMalformedBlobIsRejected(): void
    {
        try {
            Itb::open('singlemsg-triple-mac-v1', \random_bytes(64));
            $this->fail('expected ItbException');
        } catch (ItbException $e) {
            $this->assertNotNull($e->getStatus());
            $this->assertNotSame(Status::OK, $e->getStatus());
        }
    }
}
