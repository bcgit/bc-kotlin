package org.bouncycastle.kcrypto.spec.asymmetric

import KCryptoServices
import org.bouncycastle.kcrypto.KeyType
import org.bouncycastle.kcrypto.spec.SignGenSpec
import org.bouncycastle.kcrypto.spec.SignPairGenSpec
import org.bouncycastle.kcrypto.spec.VerifyGenSpec
import java.security.SecureRandom

/**
 * Specification class for generating EC key pairs.
 */
class ECGenSpec(val name: String, override val random: SecureRandom): SignPairGenSpec {

    constructor(curveName: String) : this(curveName, KCryptoServices.secureRandom)

    init {
        // todo
    }

    override val signType get() = ECGenSpec.signType
    override val verifyType get() = ECGenSpec.verifyType

    companion object: SignGenSpec, VerifyGenSpec {
        override val signType = KeyType.SIGNING.forAlgorithm("EC")
        override val verifyType = KeyType.VERIFICATION.forAlgorithm("EC")
    }
}