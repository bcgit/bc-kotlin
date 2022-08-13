package org.bouncycastle.kcrypto.spec.asymmetric

import KCryptoServices
import org.bouncycastle.kcrypto.KeyType
import org.bouncycastle.kcrypto.spec.SignGenSpec
import org.bouncycastle.kcrypto.spec.SignPairGenSpec
import org.bouncycastle.kcrypto.spec.VerifyGenSpec
import java.security.SecureRandom

class FalconGenSpec(val parameterSet: String, override val random: SecureRandom): SignPairGenSpec {
    constructor(parameterSet: String) : this(parameterSet, KCryptoServices.secureRandom)

    override val signType get() = FalconGenSpec.signType
    override val verifyType get() = FalconGenSpec.verifyType

    companion object: SignGenSpec, VerifyGenSpec {
        override val signType = KeyType.SIGNING.forAlgorithm("Falcon")
        override val verifyType = KeyType.VERIFICATION.forAlgorithm("Falcon")
    }
}