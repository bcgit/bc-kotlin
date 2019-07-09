package org.bouncycastle.kcrypto

import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.spec.AlgSpec

/**
 * A public/private key pair for encryption/decryption operations.
 *
 * @property decryptionKey private key component
 * @property encryptionKey public key component
 */
class EncryptingKeyPair(internal val kp: KeyPair) {
    val decryptionKey: DecryptionKey = BaseDecryptionKey(kp.privateKey)
    val encryptionKey: EncryptionKey = BaseEncryptionKey(kp.publicKey)

    fun singleBlockEncryptor(algorithm: AlgSpec<AlgorithmIdentifier>): SingleBlockEncryptor<AlgorithmIdentifier> {
        return encryptionKey.singleBlockEncryptor(algorithm)
    }

    fun keyWrapper(algorithm: AlgSpec<AlgorithmIdentifier>): KeyWrapper<AlgorithmIdentifier> {
        return encryptionKey.keyWrapper(algorithm)
    }

    fun singleBlockDecryptor(algorithm: AlgSpec<AlgorithmIdentifier>): SingleBlockDecryptor<AlgorithmIdentifier> {
        return decryptionKey.singleBlockDecryptor(algorithm)
    }

    fun keyUnwrapper(algorithm: AlgSpec<AlgorithmIdentifier>): KeyUnwrapper<AlgorithmIdentifier> {
        return decryptionKey.keyUnwrapper(algorithm)
    }
}