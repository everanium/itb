// eitb — command-line demonstrator for the ITB Java binding.
//
// Subcommands:
//
//   eitb version                                   library + binding versions
//   eitb profiles                                  registered profile catalogue
//   eitb encrypt <profile> <in-file> <out-file>    Single Message encrypt
//   eitb decrypt <profile> <blob-hex> <in-file> <out-file>
//
// `encrypt` prints the session blob to stderr as hex; feed that hex
// back to `decrypt` on the receiving side. `profiles` lists the
// registered profile catalogue one name per line; the profiles that
// carry a cipher surface are the ones `encrypt` / `decrypt` accept.

package com.everanium.itb.eitb;

import com.everanium.itb.Pipeline;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public final class Main {

    private Main() {
    }

    public static void main(String[] args) {
        // Defensive heap caps — the CLI can be run on gigabyte files.
        com.everanium.itb.Runtime.setMemoryLimit(512L << 20);
        com.everanium.itb.Runtime.setGCPercent(20);
        try {
            switch (args.length > 0 ? args[0] : "") {
                case "version":
                    if (args.length == 1) {
                        cmdVersion();
                        return;
                    }
                    break;
                case "profiles":
                    if (args.length == 1) {
                        cmdProfiles();
                        return;
                    }
                    break;
                case "encrypt":
                    if (args.length == 4) {
                        cmdEncrypt(args[1], args[2], args[3]);
                        return;
                    }
                    break;
                case "decrypt":
                    if (args.length == 5) {
                        cmdDecrypt(args[1], args[2], args[3], args[4]);
                        return;
                    }
                    break;
                default:
                    break;
            }
        } catch (Exception e) {
            System.err.println("eitb: " + e.getMessage());
            System.exit(1);
        }
        System.err.println(
                "usage: eitb version\n"
                + "       eitb profiles\n"
                + "       eitb encrypt <profile> <in-file> <out-file>\n"
                + "       eitb decrypt <profile> <blob-hex> <in-file> <out-file>");
        System.exit(2);
    }

    private static void cmdVersion() {
        System.out.println("libitb " + com.everanium.itb.Runtime.version());
        System.out.println("itb-java " + com.everanium.itb.Runtime.BINDING_VERSION);
    }

    // Prints the registered profile catalogue one name per line in
    // the sorted order Pipeline.profiles() returns.
    private static void cmdProfiles() {
        for (String name : Pipeline.profiles()) {
            System.out.println(name);
        }
    }

    // Profiles whose canonical name begins with "streaming-" route
    // through the one-shot streaming buffered pair instead of the
    // Single Message pair.
    private static boolean isStreamingProfile(String profile) {
        return profile.startsWith("streaming-");
    }

    // Recursively create the parent directory of `path` (mkdir -p).
    private static void ensureParentDir(String path) throws IOException {
        Path parent = Path.of(path).toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
    }

    private static void cmdEncrypt(String profile, String inFile, String outFile)
            throws IOException {
        byte[] plain = Files.readAllBytes(Path.of(inFile));
        try (Pipeline pipe = Pipeline.init(profile)) {
            byte[] wire = isStreamingProfile(profile)
                    ? pipe.encryptStreamOneShot(plain)
                    : pipe.encryptMessage(plain);
            ensureParentDir(outFile);
            Files.write(Path.of(outFile), wire);
            System.err.println(hexEncode(pipe.save()));
            System.out.printf("encrypted %s -> %s (%d -> %d bytes)%n",
                    inFile, outFile, plain.length, wire.length);
        }
    }

    private static void cmdDecrypt(String profile, String blobHex,
            String inFile, String outFile) throws IOException {
        byte[] blob = hexDecode(blobHex);
        byte[] wire = Files.readAllBytes(Path.of(inFile));
        try (Pipeline pipe = Pipeline.load(blob)) {
            byte[] plain = isStreamingProfile(profile)
                    ? pipe.decryptStreamOneShot(wire)
                    : pipe.decryptMessage(wire);
            ensureParentDir(outFile);
            Files.write(Path.of(outFile), plain);
            System.out.printf("decrypted %s -> %s (%d -> %d bytes)%n",
                    inFile, outFile, wire.length, plain.length);
        }
    }

    private static String hexEncode(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            out.append(String.format("%02x", b));
        }
        return out.toString();
    }

    /** Hex decode tolerant to case, whitespace, and a 0x prefix. */
    private static byte[] hexDecode(String s) {
        String clean = s.replaceAll("\\s+", "");
        if (clean.startsWith("0x") || clean.startsWith("0X")) {
            clean = clean.substring(2);
        }
        if (clean.length() % 2 != 0) {
            throw new IllegalArgumentException("blob hex has odd length");
        }
        byte[] out = new byte[clean.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(clean.charAt(2 * i), 16);
            int lo = Character.digit(clean.charAt(2 * i + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException(
                        "blob hex: bad digit at offset " + (2 * i));
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }
}
