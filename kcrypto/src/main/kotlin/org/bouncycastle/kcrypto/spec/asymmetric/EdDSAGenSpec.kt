package org.bouncycastle.kcrypto.spec.asymmetric

import KCryptoServices
import org.bouncycastle.kcrypto.KeyType
import org.bouncycastle.kcrypto.spec.SignGenSpec
import org.bouncycastle.kcrypto.spec.SignPairGenSpec
import org.bouncycastle.kcrypto.spec.VerifyGenSpec
import java.security.SecureRandom

class EdDSAGenSpec(val curveName: String, override val random: SecureRandom): SignPairGenSpec {
    constructor(curveName: String) : this(curveName, KCryptoServices.secureRandom)

    override val signType get() = EdDSAGenSpec.signType
    override val verifyType get() = EdDSAGenSpec.verifyType

    companion object: SignGenSpec, VerifyGenSpec {
        override val signType = KeyType.SIGNING.forAlgorithm("EdDSA")
        override val verifyType = KeyType.VERIFICATION.forAlgorithm("EdDSA")
    }
}