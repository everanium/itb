package com.everanium.itb;

/**
 * Incremental encrypt session: plaintext in via {@code write}, wire
 * out via {@code read}. Obtained from {@link Pipeline#encryptStream()};
 * the session holds a reference to its parent Pipeline for its whole
 * lifetime.
 */
public final class EncryptStream extends StreamSession {

    EncryptStream(Pipeline parent) {
        super(parent, true);
    }
}
