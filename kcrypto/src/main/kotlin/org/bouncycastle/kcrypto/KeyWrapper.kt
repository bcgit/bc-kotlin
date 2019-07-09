package org.bouncycastle.kcrypto

/**
 * Instances can perform key wrapping.
 */
interface KeyWrapper<T> {
    val algorithmIdentifier: T

    fun wrap(key: SymmetricKey): ByteArray

    fun wrap(key: SigningKey): ByteArray
}