package org.bouncycastle.kcrypto.spec.asymmetric

import KCryptoServices
import org.bouncycastle.kcrypto.KeyType
import org.bouncycastle.kcrypto.spec.SignGenSpec
import org.bouncycastle.kcrypto.spec.SignPairGenSpec
import org.bouncycastle.kcrypto.spec.VerifyGenSpec
import java.security.SecureRandom

class DilithiumGenSpec(val parameterSet: String, override val random: SecureRandom): SignPairGenSpec {
    constructor(parameterSet: String) : this(parameterSet, KCryptoServices.secureRandom)

    override val signType get() = DilithiumGenSpec.signType
    override val verifyType get() = DilithiumGenSpec.verifyType

    companion object: SignGenSpec, VerifyGenSpec {
        override val signType = KeyType.SIGNING.forAlgorithm("Dilithium")
        override val verifyType = KeyType.VERIFICATION.forAlgorithm("Dilithium")
    }
}