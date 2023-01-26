package org.bouncycastle.kcrypto.spec.asymmetric

import KCryptoServices
import org.bouncycastle.kcrypto.KeyType
import org.bouncycastle.kcrypto.spec.*
import java.security.SecureRandom

class KyberGenSpec(val parameterSet: String, override val random: SecureRandom): EncPairGenSpec {
    constructor(parameterSet: String) : this(parameterSet, KCryptoServices.secureRandom)

    override val decType get() = KyberGenSpec.decType
    override val encType get() = KyberGenSpec.encType

    companion object: EncGenSpec, DecGenSpec {
        override val decType = KeyType.DECRYPTION.forAlgorithm("Kyber")
        override val encType = KeyType.ENCRYPTION.forAlgorithm("Kyber")
    }
}