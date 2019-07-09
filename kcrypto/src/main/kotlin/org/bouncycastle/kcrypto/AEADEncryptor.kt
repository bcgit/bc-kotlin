package org.bouncycastle.kcrypto

import java.io.OutputStream

/**
 * Base operator interface for encrypting data using AEAD encryption.
 */
interface AEADEncryptor<T>: Encryptor<T>
{
    /**
     * Return an encryptor writing its output to the passed in stream destStream.
     *
     * @param destStream the stream encrypted data is to be written to.
     * @return an encryptor which writes out encrypted data produced using an AEAD encryption.
     */
    override fun outputEncryptor(destStream: OutputStream): OutputAEADEncryptor<T>
}