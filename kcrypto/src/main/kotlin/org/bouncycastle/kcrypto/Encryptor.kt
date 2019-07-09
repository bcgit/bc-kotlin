package org.bouncycastle.kcrypto

import java.io.OutputStream

/**
 * Encrypts a stream.
 */
interface Encryptor<T>
{
    fun outputEncryptor(destStream: OutputStream): OutputEncryptor<T>
}