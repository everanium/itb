package com.everanium.itb;

/**
 * Incremental decrypt session: wire in via {@code write}, plaintext
 * out via {@code read}. Obtained from {@link Pipeline#decryptStream()};
 * the session holds a reference to its parent Pipeline for its whole
 * lifetime.
 */
public final class DecryptStream extends StreamSession {

    DecryptStream(Pipeline parent) {
        super(parent, false);
    }
}
