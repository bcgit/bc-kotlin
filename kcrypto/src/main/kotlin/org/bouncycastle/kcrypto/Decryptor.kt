package org.bouncycastle.kcrypto

import java.io.InputStream
import java.io.OutputStream

interface Decryptor<T>
{
    val algorithmIdentifier: T

    fun outputDecryptor(destStream: OutputStream): OutputDecryptor<T>

    fun inputDecryptor(sourceStream: InputStream): InputDecryptor<T>
}