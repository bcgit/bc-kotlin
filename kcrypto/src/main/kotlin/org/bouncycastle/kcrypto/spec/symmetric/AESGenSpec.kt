package org.bouncycastle.kcrypto.spec.symmetric

import KCryptoServices
import org.bouncycastle.kcrypto.AuthenticationKey
import org.bouncycastle.kcrypto.KeyType
import org.bouncycastle.kcrypto.SymmetricKey
import org.bouncycastle.kcrypto.spec.AuthGenSpec
import org.bouncycastle.kcrypto.spec.AuthKeyGenSpec
import org.bouncycastle.kcrypto.spec.SymGenSpec
import org.bouncycastle.kcrypto.spec.SymKeyGenSpec
import java.security.SecureRandom

/**
 * AES key generator specification
 */
class AESGenSpec(val keySize: Int, override val random: SecureRandom): AuthKeyGenSpec, SymKeyGenSpec {
    constructor(keySize: Int) : this(keySize, KCryptoServices.secureRandom)

    init {
        if (keySize != 256 && keySize != 192 && keySize != 128) {
            throw IllegalArgumentException("keySize must be one of (128, 192, 256)")
        }
    }

    override val symType: KeyType<SymmetricKey> get() = AESGenSpec.symType
    override val authType: KeyType<AuthenticationKey> get() = AESGenSpec.authType

    companion object: AuthGenSpec, SymGenSpec {
        override val symType = KeyType.SYMMETRIC.forAlgorithm("AES")
        override val authType = KeyType.AUTHENTICATION.forAlgorithm("AES")
    }
}