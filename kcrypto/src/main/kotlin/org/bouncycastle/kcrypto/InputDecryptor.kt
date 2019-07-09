package org.bouncycastle.kcrypto

import java.io.Closeable
import java.io.InputStream

/**
 * Instances can perform decryption of a steam.
 */
interface InputDecryptor<T>: Closeable
{
    val algorithmIdentifier: T

    val decStream: InputStream
}