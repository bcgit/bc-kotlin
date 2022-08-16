package org.bouncycastle.kcrypto.spec.asymmetric

import KCryptoServices
import org.bouncycastle.kcrypto.KeyType
import org.bouncycastle.kcrypto.spec.SignGenSpec
import org.bouncycastle.kcrypto.spec.SignPairGenSpec
import org.bouncycastle.kcrypto.spec.VerifyGenSpec
import java.security.SecureRandom

class SPHINCSPlusGenSpec(val parameterSet: String, override val random: SecureRandom): SignPairGenSpec {
    constructor(parameterSet: String) : this(parameterSet, KCryptoServices.secureRandom)

    override val signType get() = SPHINCSPlusGenSpec.signType
    override val verifyType get() = SPHINCSPlusGenSpec.verifyType

    companion object: SignGenSpec, VerifyGenSpec {
        override val signType = KeyType.SIGNING.forAlgorithm("SPHINCSPlus")
        override val verifyType = KeyType.VERIFICATION.forAlgorithm("SPHINCSPlus")
    }
}