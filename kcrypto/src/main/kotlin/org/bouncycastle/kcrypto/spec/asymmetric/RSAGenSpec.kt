package org.bouncycastle.kcrypto.spec.asymmetric

import KCryptoServices
import org.bouncycastle.kcrypto.*
import org.bouncycastle.kcrypto.spec.*
import java.math.BigInteger
import java.security.SecureRandom
import java.security.spec.RSAKeyGenParameterSpec

/**
 * RSA Key Generator specification.
 */
class RSAGenSpec(val keySize: Int, val publicExponent: BigInteger, override val random: SecureRandom) : SignPairGenSpec, EncPairGenSpec {

    constructor(keySize: Int, random: SecureRandom) : this(keySize, RSAKeyGenParameterSpec.F4, random)
    constructor(keySize: Int) : this(keySize, RSAKeyGenParameterSpec.F4, KCryptoServices.secureRandom)

    init {
        // todo
    }

    override val decType: KeyType<DecryptionKey> get() = RSAGenSpec.decType
    override val encType: KeyType<EncryptionKey> get() = RSAGenSpec.encType

    override val signType: KeyType<SigningKey> get() = RSAGenSpec.signType
    override val verifyType: KeyType<VerificationKey> get() = RSAGenSpec.verifyType

    companion object: SignGenSpec, VerifyGenSpec, EncGenSpec, DecGenSpec {

        override val signType = KeyType.SIGNING.forAlgorithm("RSA")
        override val verifyType = KeyType.VERIFICATION.forAlgorithm("RSA")

        override val decType = KeyType.DECRYPTION.forAlgorithm("RSA")

        override val encType = KeyType.ENCRYPTION.forAlgorithm("RSA")
    }
}