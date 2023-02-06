package org.bouncycastle.kcrypto.spec.symmetric

import KCryptoServices
import org.bouncycastle.kcrypto.AuthenticationKey
import org.bouncycastle.kcrypto.KeyType
import org.bouncycastle.kcrypto.spec.AuthKeyGenSpec
import java.security.SecureRandom

/**
 * HMAC SHA-512 key generator specification.
 */
class HMacGenSpec(val algName: String, val keySize: Int, override val random: SecureRandom): AuthKeyGenSpec
{
    constructor(algName: String, keySize: Int): this(algName, keySize, KCryptoServices.secureRandom)

    override val authType: KeyType<AuthenticationKey> get() = KeyType.AUTHENTICATION.forAlgorithm(this.algName)
}