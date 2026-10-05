<?php

declare(strict_types=1);

namespace Everanium\Itb3\Tests;

use Everanium\Itb3\Itb;
use Everanium\Itb3\ItbException;
use Everanium\Itb3\Status;
use PHPUnit\Framework\TestCase;

/**
 * Runtime surface: the process-wide Go knobs (heap limit, GC
 * percentage, GOMAXPROCS, heap profile, pool counters) and the shipped
 * inner-hash registry enumeration.
 */
final class RuntimeTest extends TestCase
{
    public function testSetGomaxprocsQueriesThenRestores(): void
    {
        // A non-positive argument queries without changing; the setter
        // returns the value that was in force before it.
        $before = Itb::setGomaxprocs(0);
        $this->assertGreaterThan(0, $before);
        $this->assertSame($before, Itb::setGomaxprocs(2));
        $this->assertSame(2, Itb::setGomaxprocs(0));
        Itb::setGomaxprocs($before);
        $this->assertSame($before, Itb::setGomaxprocs(0));
    }

    public function testWriteHeapProfileWritesAReadableProfile(): void
    {
        $dir = \sys_get_temp_dir() . '/itb3-heapprof-' . \bin2hex(\random_bytes(6));
        $this->assertTrue(\mkdir($dir, 0700));
        $path = $dir . '/heap.prof';
        try {
            Itb::writeHeapProfile($path);
            $this->assertGreaterThan(0, \filesize($path));
            // pprof profiles are gzip-wrapped protobuf.
            $this->assertSame("\x1f\x8b", \file_get_contents($path, false, null, 0, 2));
        } finally {
            @\unlink($path);
            @\rmdir($dir);
        }
    }

    public function testWriteHeapProfileReportsTheOsDiagnostic(): void
    {
        try {
            Itb::writeHeapProfile('/no-such-directory-itb3-test/heap.prof');
            $this->fail('expected ItbException');
        } catch (ItbException $e) {
            $this->assertSame(Status::BAD_INPUT, $e->getStatus());
            $this->assertStringContainsString('heap.prof', $e->getDetail());
        }
    }

    public function testPoolStatsLengthMatchesTheDeclaredLayout(): void
    {
        $length = Itb::poolStatsLen();
        $this->assertGreaterThan(0, $length);
        $stats = Itb::poolStats();
        $this->assertCount($length, $stats);
        $tiers = $stats[0];
        // Slot 0 carries the tier count T; the vector is 1 + 5*T + 8.
        $this->assertGreaterThan(0, $tiers);
        $this->assertSame($length, 1 + 5 * $tiers + 8);
    }

    public function testPoolStatsCountersAreMonotonicAcrossWork(): void
    {
        $before = Itb::poolStats();
        $pipe = Itb::create('singlemsg-triple-mac-v1');
        $pipe->decryptMessage($pipe->encryptMessage(\str_repeat('x', 4096)));
        $pipe->free();
        $after = Itb::poolStats();
        $this->assertCount(\count($before), $after);
        for ($i = 1; $i < \count($after); $i++) {
            $this->assertGreaterThanOrEqual($before[$i], $after[$i]);
        }
        $this->assertGreaterThan(
            \array_sum(\array_slice($before, 1)),
            \array_sum(\array_slice($after, 1))
        );
    }

    public function testMemoryLimitAndGcPercentQueryWithoutChanging(): void
    {
        $limit = Itb::setMemoryLimit(-1);
        $this->assertSame($limit, Itb::setMemoryLimit(-1));
        $pct = Itb::setGcPercent(-1);
        $this->assertSame($pct, Itb::setGcPercent(-1));
    }

    public function testHashNamesEnumeratesTheShippedRegistry(): void
    {
        $names = Itb::hashNames();
        $this->assertGreaterThan(1, \count($names));
        $this->assertCount(\count($names), \array_unique($names));
        foreach ($names as $name) {
            $this->assertIsString($name);
            $this->assertNotSame('', $name);
        }
        // The enumeration is what a caller validates a primitive name
        // against, so a shipped name resolves and a typo does not.
        $this->assertContains('areion512', $names);
        $this->assertNotContains('areion512-nope', $names);
    }

    public function testEveryEnumeratedNameConstructsAPipeline(): void
    {
        foreach (Itb::hashNames() as $name) {
            $pipe = Itb::create('singlemsg-triple-nomac-v1', [
                'innerHash' => $name,
                'withParallax' => false,
            ]);
            $this->assertSame(
                'registry probe',
                $pipe->decryptMessage($pipe->encryptMessage('registry probe'))
            );
            $pipe->free();
        }
    }
}
