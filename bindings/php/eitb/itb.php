<?php

/**
 * eitb — command-line demonstrator for the ITB PHP binding.
 *
 * Subcommands:
 *
 *     eitb version                                   library + binding versions
 *     eitb profiles                                  registered profile catalogue
 *     eitb inspect <blob-hex>                        profile record of a blob
 *     eitb encrypt <profile> <in-file> <out-file>    Single Message encrypt
 *     eitb decrypt <profile> <blob-hex> <in-file> <out-file>
 *
 * `encrypt` prints the session blob (Pipeline::save()) to stderr as
 * hex; feed that hex back to `decrypt` on the receiving side, which
 * reopens the session with Itb::load() (the profile argument only
 * routes Single Message versus streaming). `profiles` lists the
 * registered profile catalogue one name per line; the profiles that
 * carry a cipher surface are the ones `encrypt` / `decrypt` accept.
 */

declare(strict_types=1);

require __DIR__ . '/../autoload.php';

use Everanium\Itb\Itb;
use Everanium\Itb\ItbException;

const USAGE = <<<'TXT'
usage: eitb version
       eitb profiles
       eitb inspect <blob-hex>
       eitb encrypt <profile> <in-file> <out-file>
       eitb decrypt <profile> <blob-hex> <in-file> <out-file>
TXT;

function cmd_version(): void
{
    echo 'libitb ', Itb::version(), "\n";
    echo 'itb-php ', Itb::VERSION, "\n";
}

function cmd_profiles(): void
{
    foreach (Itb::profiles() as $name) {
        echo $name, "\n";
    }
}

function read_file(string $path): string
{
    $data = @file_get_contents($path);
    if ($data === false) {
        throw new ItbException("cannot read file: $path");
    }
    return $data;
}

function write_file(string $path, string $data): void
{
    if (@file_put_contents($path, $data) === false) {
        throw new ItbException("cannot write file: $path");
    }
}

/**
 * Profiles whose canonical name begins with "streaming-" route
 * through the one-shot streaming buffered pair instead of the
 * Single Message pair.
 */
function is_streaming_profile(string $profile): bool
{
    return str_starts_with($profile, 'streaming-');
}

/** Recursively create the parent directory of $path (mkdir -p). */
function ensure_parent_dir(string $path): void
{
    $parent = dirname($path);
    if ($parent !== '' && $parent !== '.' && !is_dir($parent)) {
        if (!mkdir($parent, 0755, true) && !is_dir($parent)) {
            throw new ItbException("cannot create directory: $parent");
        }
    }
}

function cmd_encrypt(string $profile, string $infile, string $outfile): void
{
    $plain = read_file($infile);
    $pipe = Itb::create($profile);
    $wire = is_streaming_profile($profile)
        ? $pipe->encryptStreamOneShot($plain)
        : $pipe->encryptMessage($plain);
    ensure_parent_dir($outfile);
    write_file($outfile, $wire);
    fwrite(STDERR, bin2hex($pipe->save()) . "\n");
    $pipe->free();
    printf("encrypted %s -> %s (%d -> %d bytes)\n", $infile, $outfile, strlen($plain), strlen($wire));
}

function blob_from_hex(string $blobHex): string
{
    $blob = @hex2bin(trim($blobHex));
    if ($blob === false) {
        throw new ItbException('blob hex: invalid hexadecimal string');
    }
    return $blob;
}

function cmd_inspect(string $blobHex): void
{
    echo json_encode(Itb::inspect(blob_from_hex($blobHex)), JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR), "\n";
}

function cmd_decrypt(string $profile, string $blobHex, string $infile, string $outfile): void
{
    $blob = blob_from_hex($blobHex);
    $wire = read_file($infile);
    $pipe = Itb::load($blob);
    $plain = is_streaming_profile($profile)
        ? $pipe->decryptStreamOneShot($wire)
        : $pipe->decryptMessage($wire);
    $pipe->free();
    ensure_parent_dir($outfile);
    write_file($outfile, $plain);
    printf("decrypted %s -> %s (%d -> %d bytes)\n", $infile, $outfile, strlen($wire), strlen($plain));
}

/** @param list<string> $argv */
function main(array $argv): int
{
    $n = count($argv);
    $knownShape = ($n === 1 && in_array($argv[0], ['version', 'profiles'], true))
        || ($n === 2 && $argv[0] === 'inspect')
        || ($n === 4 && $argv[0] === 'encrypt')
        || ($n === 5 && $argv[0] === 'decrypt');
    if (!$knownShape) {
        fwrite(STDERR, USAGE . "\n");
        return 2;
    }
    // Large files pass through PHP strings; lift the CLI memory cap.
    ini_set('memory_limit', '-1');
    try {
        // Go-runtime pacing caps applied before any cipher work.
        Itb::setMemoryLimit(512 << 20);
        Itb::setGcPercent(20);
        switch ($argv[0]) {
            case 'version':
                cmd_version();
                break;
            case 'profiles':
                cmd_profiles();
                break;
            case 'inspect':
                cmd_inspect($argv[1]);
                break;
            case 'encrypt':
                cmd_encrypt($argv[1], $argv[2], $argv[3]);
                break;
            default:
                cmd_decrypt($argv[1], $argv[2], $argv[3], $argv[4]);
        }
    } catch (ItbException $e) {
        fwrite(STDERR, 'eitb: ' . $e->getMessage() . "\n");
        return 1;
    }
    return 0;
}

exit(main(array_slice($_SERVER['argv'], 1)));
