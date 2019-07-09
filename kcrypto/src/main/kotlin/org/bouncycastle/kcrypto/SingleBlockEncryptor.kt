package org.bouncycastle.kcrypto

interface SingleBlockEncryptor<T> {
    val algorithmIdentifier: T

    fun encrypt(data: ByteArray): ByteArray
}

