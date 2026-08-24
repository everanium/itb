<?php

declare(strict_types=1);

namespace Everanium\Itb\Tests;

use Everanium\Itb\FFIBridge;
use Everanium\Itb\Itb;
use PHPUnit\Framework\TestCase;

/**
 * Library reachability, version string, hash roster canonical order,
 * profile roster, and the Go runtime knobs.
 */
final class SmokeTest extends TestCase
{
    public function testVersionIsNonEmptySemver(): void
    {
        $v = Itb::version();
        $this->assertNotSame('', $v);
        $this->assertMatchesRegularExpression('/^\d+\.\d+\.\d+/', $v);
    }

    public function testHashesCanonicalOrder(): void
    {
        // The shipped registry roster in canonical order; widths are
        // the native ChainHash widths in bits.
        $expected = [
            'areion256' => 256,
            'areion512' => 512,
            'blake2b256' => 256,
            'blake2b512' => 512,
            'blake2s' => 256,
            'blake3' => 256,
            'aescmac' => 128,
            'siphash24' => 128,
            'chacha20' => 256,
        ];
        $this->assertSame($expected, Itb::hashes());
    }

    public function testProfilesRosterShape(): void
    {
        $profiles = Itb::profiles();
        $this->assertNotEmpty($profiles);
        foreach ([
            'streaming-aead-triple-mac-v1',
            'streaming-noaead-triple-v1',
            'singlemsg-triple-mac-v1',
            'singlemsg-triple-nomac-v1',
        ] as $name) {
            $this->assertContains($name, $profiles);
        }
        // Every shipped cipher profile constructs a Pipeline (the
        // blob-only profile included — it just has no cipher surface).
        foreach ($profiles as $name) {
            $pipe = Itb::create($name);
            $this->assertNotSame('', $pipe->blob(), $name);
            $pipe->free();
        }
    }

    public function testRuntimeKnobsQueryWithoutChanging(): void
    {
        // Negative values query without changing; the return is the
        // previous setting.
        $prevLimit = Itb::setMemoryLimit(-1);
        $this->assertIsInt($prevLimit);
        $prevGc = Itb::setGcPercent(-1);
        $this->assertIsInt($prevGc);
    }

    public function testLastErrorIsStringAccessor(): void
    {
        $this->assertIsString(Itb::lastError());
        $this->assertIsString(FFIBridge::lastError());
    }
}
