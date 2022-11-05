package org.bouncycastle.kcrypto.spec.asymmetric

import KCryptoServices
import org.bouncycastle.kcrypto.KeyType
import org.bouncycastle.kcrypto.spec.SignGenSpec
import org.bouncycastle.kcrypto.spec.SignPairGenSpec
import org.bouncycastle.kcrypto.spec.VerifyGenSpec
import java.security.SecureRandom

class LMSGenSpec(val sigParameterSet: String, val otsParameterSet: String,  override val random: SecureRandom): SignPairGenSpec {
    constructor(sigParameterSet: String, otsParameterSet: String) : this(sigParameterSet, otsParameterSet, KCryptoServices.secureRandom)

    override val signType get() = LMSGenSpec.signType
    override val verifyType get() = LMSGenSpec.verifyType

    companion object: SignGenSpec, VerifyGenSpec {
        override val signType = KeyType.SIGNING.forAlgorithm("LMS")
        override val verifyType = KeyType.VERIFICATION.forAlgorithm("LMS")
    }
}