package org.bouncycastle.kcrypto

import java.io.Closeable
import java.io.OutputStream

interface OutputDecryptor<T>: Closeable
{
    val algorithmIdentifier: T

    val decStream: OutputStream
}