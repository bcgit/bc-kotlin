package org.bouncycastle.kcrypto

interface SingleBlockDecryptor<T> {
    val algorithmIdentifier: T

    fun decrypt(data: ByteArray): ByteArray
}
