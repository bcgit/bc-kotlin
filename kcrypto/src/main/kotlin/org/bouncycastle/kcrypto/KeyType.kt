package org.bouncycastle.kcrypto

import org.bouncycastle.asn1.x509.AlgorithmIdentifier

abstract class KeyType<T>(val algorithm: String) {

    internal abstract fun forAlgorithm(specificAlg: String): KeyType<T>

    internal abstract fun forAlgorithm(specificAlg: AlgorithmIdentifier): KeyType<T>

    companion object {
        val DECRYPTION: KeyType<DecryptionKey> = BaseKeyType("Decryption")
        val ENCRYPTION: KeyType<EncryptionKey> = BaseKeyType("Encryption")
        val SIGNING: KeyType<SigningKey> = BaseKeyType("Signing")
        val VERIFICATION: KeyType<VerificationKey> = BaseKeyType("Verification")

        val SYMMETRIC: KeyType<SymmetricKey> = BaseKeyType("Symmetric")
        val AUTHENTICATION: KeyType<AuthenticationKey> = BaseKeyType("Authentication")
    }
}

internal class BaseKeyType<T>(algorithm: String): KeyType<T>(algorithm)
{
    override fun forAlgorithm(specificAlg: String): KeyType<T> {
        return BaseKeyType(specificAlg)
    }

    override fun forAlgorithm(specificAlg: AlgorithmIdentifier): KeyType<T> {
        return BaseKeyType(specificAlg.algorithm.id)
    }
}