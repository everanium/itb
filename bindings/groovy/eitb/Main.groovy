// eitb — command-line demonstrator for the ITB Groovy binding.
//
// Subcommands:
//
//   eitb version                                   library + binding versions
//   eitb hashes                                    shipped hash primitive roster
//   eitb encrypt <profile> <in-file> <out-file>    Single Message encrypt
//   eitb decrypt <profile> <blob-hex> <in-file> <out-file>
//
// `encrypt` prints the session blob to stderr as hex; feed that hex
// back to `decrypt` on the receiving side.
//
// The `hashes` diagnostic iterates the registry through the Java
// binding's diagnostic accessor — the binding library itself
// deliberately exposes no primitive enumeration.

package dev.everanium.itb.groovy.eitb

import groovy.transform.CompileStatic

import java.nio.file.Files
import java.nio.file.Paths

import com.everanium.itb.HashRoster

import dev.everanium.itb.groovy.ItbException
import dev.everanium.itb.groovy.Pipeline
import dev.everanium.itb.groovy.Runtime

@CompileStatic
final class Main {

    private Main() {
    }

    static void main(String[] args) {
        Runtime.setMemoryLimit(512L * 1024 * 1024)
        Runtime.setGCPercent(20)
        int rc
        try {
            rc = dispatch(args)
        } catch (ItbException e) {
            System.err.println("eitb: ${e.message}")
            rc = 1
        } catch (Exception e) {
            System.err.println("eitb: ${e.message}")
            rc = 1
        }
        System.exit(rc)
    }

    private static int dispatch(String[] args) {
        if (args.length == 1 && args[0] == 'version') {
            return cmdVersion()
        }
        if (args.length == 1 && args[0] == 'hashes') {
            return cmdHashes()
        }
        if (args.length == 4 && args[0] == 'encrypt') {
            return cmdEncrypt(args[1], args[2], args[3])
        }
        if (args.length == 5 && args[0] == 'decrypt') {
            return cmdDecrypt(args[1], args[2], args[3], args[4])
        }
        System.err.println('''usage: eitb version
       eitb hashes
       eitb encrypt <profile> <in-file> <out-file>
       eitb decrypt <profile> <blob-hex> <in-file> <out-file>''')
        2
    }

    private static int cmdVersion() {
        println "libitb ${Runtime.version()}"
        println "itb-groovy ${Runtime.BINDING_VERSION}"
        0
    }

    private static int cmdHashes() {
        HashRoster.print()
        0
    }

    // Profiles whose canonical name begins with "streaming-" route
    // through the one-shot streaming buffered pair instead of the
    // Single Message pair.
    private static boolean isStreamingProfile(String profile) {
        profile.startsWith('streaming-')
    }

    private static void ensureParentDir(String path) {
        File parent = new File(path).parentFile
        if (parent != null) {
            parent.mkdirs()
        }
    }

    private static int cmdEncrypt(String profile, String inFile, String outFile) {
        byte[] plain = Files.readAllBytes(Paths.get(inFile))
        Pipeline.withPipeline(profile) { Pipeline pipe ->
            byte[] wire = isStreamingProfile(profile) ?
                pipe.encryptStreamOneShot(plain) :
                pipe.encryptMessage(plain)
            ensureParentDir(outFile)
            Files.write(Paths.get(outFile), wire)
            System.err.println(hex(pipe.blob))
            println "encrypted $inFile -> $outFile (${plain.length} -> ${wire.length} bytes)"
        }
        0
    }

    private static int cmdDecrypt(String profile, String blobHex, String inFile, String outFile) {
        byte[] blob = unhex(blobHex)
        byte[] wire = Files.readAllBytes(Paths.get(inFile))
        Pipeline.withOpened(profile, blob) { Pipeline pipe ->
            byte[] plain = isStreamingProfile(profile) ?
                pipe.decryptStreamOneShot(wire) :
                pipe.decryptMessage(wire)
            ensureParentDir(outFile)
            Files.write(Paths.get(outFile), plain)
            println "decrypted $inFile -> $outFile (${wire.length} -> ${plain.length} bytes)"
        }
        0
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2)
        for (byte b : bytes) {
            sb.append(String.format('%02x', b & 0xff))
        }
        sb.toString()
    }

    private static byte[] unhex(String s) {
        if (s.length() % 2 != 0) {
            throw new IllegalArgumentException('odd-length hex string')
        }
        byte[] out = new byte[s.length().intdiv(2)]
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16)
        }
        out
    }
}
