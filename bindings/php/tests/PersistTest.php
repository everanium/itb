<?php

declare(strict_types=1);

namespace Everanium\Itb3\Tests;

use Everanium\Itb3\Itb;
use Everanium\Itb3\ItbException;
use Everanium\Itb3\Status;
use PHPUnit\Framework\TestCase;

/**
 * Session persistence: save / load in memory, saveF / loadF through a
 * temp file (mode 0600), inspect, lookup / profiles, maxWorkers.
 */
final class PersistTest extends TestCase
{
    private const PROFILE = 'singlemsg-triple-mac-v1';

    public function testSaveLoadRoundTrip(): void
    {
        $sender = Itb::create(self::PROFILE);
        $blob = $sender->save();
        $this->assertNotSame('', $blob);
        $this->assertSame($blob, $sender->save(), 'save is stable between calls');
        $receiver = Itb::load($blob);
        $this->assertSame($blob, $receiver->save(), 'load retains the blob');
        $wire = $sender->encryptMessage('in-memory persist');
        $this->assertSame('in-memory persist', $receiver->decryptMessage($wire));
        $sender->free();
        $receiver->free();
    }

    public function testSaveFLoadFRoundTrip(): void
    {
        $dir = \sys_get_temp_dir() . '/itb-php-persist-' . \bin2hex(\random_bytes(4));
        \mkdir($dir, 0700);
        $path = $dir . '/session.blob';
        try {
            $sender = Itb::create(self::PROFILE);
            $sender->saveF($path);
            \clearstatcache(true, $path);
            $this->assertSame(0600, \fileperms($path) & 0777);
            $receiver = Itb::loadF($path);
            $this->assertSame($sender->save(), $receiver->save());
            $wire = $sender->encryptMessage('file persist');
            $this->assertSame('file persist', $receiver->decryptMessage($wire));
            $sender->free();
            $receiver->free();

            try {
                Itb::loadF($dir . '/absent.blob');
                $this->fail('expected ItbException');
            } catch (ItbException $e) {
                $this->assertSame(Status::BAD_INPUT, $e->getStatus());
            }
        } finally {
            @\unlink($path);
            @\rmdir($dir);
        }
    }

    public function testLoadWithMasterOverride(): void
    {
        $sender = Itb::create(self::PROFILE);
        $rotated = $sender->rekey(\str_repeat("\x31", 32), \str_repeat("\x32", 32));
        $receiver = Itb::load($sender->save(), [\str_repeat("\x31", 32), \str_repeat("\x32", 32)]);
        $this->assertSame($rotated, $receiver->save());
        $wire = $sender->encryptMessage('master override');
        $this->assertSame('master override', $receiver->decryptMessage($wire));
        $sender->free();
        $receiver->free();
    }

    public function testInspectMatchesLookup(): void
    {
        // inspect carries the registry recipe plus the blob-only
        // nonce_bits / barrier_fill inspection fields; lookup returns
        // just the recipe.
        $pipe = Itb::create(self::PROFILE);
        $record = Itb::inspect($pipe->save());
        $pipe->free();
        $this->assertSame(self::PROFILE, $record['name']);
        $this->assertSame('singlemsg-mac', $record['mode']);
        $this->assertArrayHasKey('keybits', $record);
        $this->assertArrayHasKey('nonce_bits', $record);
        $this->assertArrayHasKey('barrier_fill', $record);
        $looked = Itb::lookup(self::PROFILE);
        $this->assertArrayNotHasKey('nonce_bits', $looked);
        $this->assertArrayNotHasKey('barrier_fill', $looked);
        $recipe = $record;
        unset($recipe['nonce_bits'], $recipe['barrier_fill'], $recipe['container_mode']);
        $this->assertSame($looked, $recipe);

        try {
            Itb::inspect('not a blob');
            $this->fail('expected ItbException');
        } catch (ItbException $e) {
            $this->assertSame(Status::BAD_INPUT, $e->getStatus());
        }
        try {
            Itb::lookup('no-such-profile');
            $this->fail('expected ItbException');
        } catch (ItbException $e) {
            $this->assertSame(Status::UNKNOWN_PROFILE, $e->getStatus());
        }
    }

    public function testMaxWorkers(): void
    {
        $pipe = Itb::create(self::PROFILE);
        $pipe->maxWorkers(2);
        $pipe->maxWorkers(-1); // clamped to auto, never rejected
        $pipe->maxWorkers(10000); // clamped to 256
        $wire = $pipe->encryptMessage('after cap change');
        $this->assertSame('after cap change', $pipe->decryptMessage($wire));
        $pipe->close();
        try {
            $pipe->maxWorkers(2);
            $this->fail('expected ItbException');
        } catch (ItbException $e) {
            $this->assertSame(Status::TRIPLE_CLOSED, $e->getStatus());
        }
        $pipe->free();

        // A negative init-time cap is clamped as well.
        $neg = Itb::create(self::PROFILE, ['maxWorkers' => -1]);
        $this->assertSame('negative cap', $neg->decryptMessage($neg->encryptMessage('negative cap')));
        $neg->free();
    }

    public function testDrbgRoundTripAndInspect(): void
    {
        foreach (['csprng', 'aesitb128'] as $name) {
            $sender = Itb::create(self::PROFILE, ['drbg' => $name]);
            $blob = $sender->save();
            $this->assertSame($name, Itb::inspect($blob)['drbg']);
            $receiver = Itb::load($blob);
            $wire = $receiver->encryptMessage("drbg {$name} round trip");
            $this->assertSame("drbg {$name} round trip", $sender->decryptMessage($wire));
            $sender->free();
            $receiver->free();
        }
    }

    public function testDrbgAbsentByDefault(): void
    {
        $pipe = Itb::create(self::PROFILE);
        $record = Itb::inspect($pipe->save());
        $pipe->free();
        $this->assertArrayNotHasKey('drbg', $record);
        $this->assertArrayNotHasKey('drbg', Itb::lookup(self::PROFILE));
    }

    public function testDrbgSurvivesRegisterCopy(): void
    {
        // drbg is a recipe field: unlike the inspection-only keys, it
        // stays in a registered copy of an inspected record.
        $pipe = Itb::create(self::PROFILE, ['drbg' => 'csprng']);
        $recipe = Itb::inspect($pipe->save());
        $pipe->free();
        unset($recipe['name'], $recipe['nonce_bits'], $recipe['barrier_fill'], $recipe['container_mode']);
        Itb::register('php-binding-test-drbg-copy', $recipe);
        $this->assertSame('csprng', Itb::lookup('php-binding-test-drbg-copy')['drbg']);
    }
}
