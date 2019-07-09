package org.bouncycastle.kcrypto

import java.io.InputStream
import java.io.OutputStream

/**
 * Base operator interface for decrypting AEAD encrypted data.
 */
interface AEADDecryptor<T>: Decryptor<T>
{
    /**
     * Return a decryptor writing its output to the passed in stream destStream.
     *
     * @param destStream the stream decrypted data is to be written to.
     * @return a decryptor which writes out decrypted data produced from an AEAD encryption.
     */
    override fun outputDecryptor(destStream: OutputStream): OutputAEADDecryptor<T>

    /**
     * Return a decryptor which reads its input from the passed in stream sourceStream.
     *
     * @param sourceStream the stream the encrypted data is to be read from.
     * @return a decryptor which produces data decrypted from a stream of AEAD encrypted data.
     */
    override fun inputDecryptor(sourceStream: InputStream): InputAEADDecryptor<T>
}