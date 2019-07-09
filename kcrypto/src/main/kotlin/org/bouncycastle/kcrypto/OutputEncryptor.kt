package org.bouncycastle.kcrypto

import java.io.Closeable
import java.io.OutputStream

interface OutputEncryptor<T>: Closeable
{
    val algorithmIdentifier: T

    val encStream: OutputStream
}