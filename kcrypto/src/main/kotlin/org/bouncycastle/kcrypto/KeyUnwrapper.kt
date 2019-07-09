package org.bouncycastle.kcrypto

/**
 * Instances can perform key unwrapping.
 */
interface KeyUnwrapper<T> {
    val algorithmIdentifier: T

    fun unwrap(wrappedKey: ByteArray, keyTemplate: KeyType<SymmetricKey>): SymmetricKey

    fun unwrap(wrappedKey: ByteArray, keyTemplate: KeyType<SigningKey>): SigningKey

    fun unwrap(wrappedKey: ByteArray, keyTemplate: KeyType<DecryptionKey>): DecryptionKey
}