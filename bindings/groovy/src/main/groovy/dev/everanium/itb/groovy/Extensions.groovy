// Groovy extension-module methods sugaring the JDK types the
// binding pumps through. Registered via the
// META-INF/groovy/org.codehaus.groovy.runtime.ExtensionModule
// descriptor, so the methods are available on plain InputStream /
// byte[] values wherever the binding jar is on the classpath.

package dev.everanium.itb.groovy

import groovy.transform.CompileStatic

/**
 * Instance-extension methods:
 *
 * <pre>{@code
 * byte[] wire  = plainBytes.encryptWith(pipe)         // Single Message
 * byte[] plain = wire.decryptWith(pipe)
 *
 * srcStream.encryptTo(pipe, dstStream)                // bounded-memory pump
 * wireStream.decryptTo(pipe, plainStream)
 * }</pre>
 */
@CompileStatic
final class Extensions {

    private Extensions() {
    }

    /** Single Message encrypt of the receiver bytes:
     * {@code plain.encryptWith(pipe)}. */
    static byte[] encryptWith(byte[] self, Pipeline pipe) {
        pipe.encryptMessage(self)
    }

    /** Receive-side counterpart of {@link #encryptWith}:
     * {@code wire.decryptWith(pipe)}. */
    static byte[] decryptWith(byte[] self, Pipeline pipe) {
        pipe.decryptMessage(self)
    }

    /** Pumps the receiver stream through an encrypt session into
     * {@code dst} with bounded memory:
     * {@code src.encryptTo(pipe, dst)}. */
    static void encryptTo(InputStream self, Pipeline pipe, OutputStream dst) {
        pipe.encryptStreamPump(self, dst)
    }

    /** Receive-side counterpart of {@link #encryptTo}:
     * {@code src.decryptTo(pipe, dst)}. */
    static void decryptTo(InputStream self, Pipeline pipe, OutputStream dst) {
        pipe.decryptStreamPump(self, dst)
    }
}
