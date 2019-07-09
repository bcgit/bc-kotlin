package org.bouncycastle.kcrypto

import java.io.OutputStream

/**
 * Base operator interface for processing associated data with AEAD ciphers.
 */
interface AADProcessor {
    /**
     * Return a stream to write associated data to in order to have it incorporated into the
     * AEAD cipher's MAC.
     *
     * @return a stream for collecting associated data.
     */
    val aadStream: OutputStream
}