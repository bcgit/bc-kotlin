package org.bouncycastle.kcrypto.spec.asymmetric

import KCryptoServices
import org.bouncycastle.kcrypto.KeyType
import org.bouncycastle.kcrypto.spec.*
import java.security.SecureRandom

class NTRUGenSpec(val parameterSet: String, override val random: SecureRandom): EncPairGenSpec {
    constructor(parameterSet: String) : this(parameterSet, KCryptoServices.secureRandom)

    override val decType get() = NTRUGenSpec.decType
    override val encType get() = NTRUGenSpec.encType

    companion object: EncGenSpec, DecGenSpec {
        override val decType = KeyType.DECRYPTION.forAlgorithm("NTRU")
        override val encType = KeyType.ENCRYPTION.forAlgorithm("NTRU")
    }
}