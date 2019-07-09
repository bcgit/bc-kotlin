package org.bouncycastle.kcrypto.spec.symmetric

import KCryptoServices
import org.bouncycastle.kcrypto.KeyType
import org.bouncycastle.kcrypto.spec.AuthGenSpec
import org.bouncycastle.kcrypto.spec.AuthKeyGenSpec
import java.security.SecureRandom

/**
 * HMAC SHA-224 key generator specification.
 */
class HMacSHA224GenSpec(val keySize: Int, override val random: SecureRandom): AuthKeyGenSpec
{
    constructor() : this(224)
    constructor(keySize: Int): this(keySize, KCryptoServices.secureRandom)

    override val authType get() = Companion.authType

    companion object: AuthGenSpec {
        override val authType = KeyType.AUTHENTICATION.forAlgorithm("HMacSHA224")
    }
}