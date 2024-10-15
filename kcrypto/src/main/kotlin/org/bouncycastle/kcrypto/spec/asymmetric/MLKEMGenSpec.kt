package org.bouncycastle.kcrypto.spec.asymmetric

import KCryptoServices
import org.bouncycastle.kcrypto.KeyType
import org.bouncycastle.kcrypto.spec.DecGenSpec
import org.bouncycastle.kcrypto.spec.EncGenSpec
import org.bouncycastle.kcrypto.spec.EncPairGenSpec
import java.security.SecureRandom

class MLKEMGenSpec(val parameterSet: String, override val random: SecureRandom): EncPairGenSpec {
    constructor(parameterSet: String) : this(parameterSet, KCryptoServices.secureRandom)

    override val decType get() = MLKEMGenSpec.decType
    override val encType get() = MLKEMGenSpec.encType

    companion object: EncGenSpec, DecGenSpec {
        override val decType = KeyType.DECRYPTION.forAlgorithm("MLKEM")
        override val encType = KeyType.ENCRYPTION.forAlgorithm("MLKEM")
    }
}