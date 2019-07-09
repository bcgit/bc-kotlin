package org.bouncycastle.kcrypto.spec.asymmetric

import KCryptoServices
import org.bouncycastle.kcrypto.KeyType
import org.bouncycastle.kcrypto.param.DSADomainParameters
import org.bouncycastle.kcrypto.spec.SignGenSpec
import org.bouncycastle.kcrypto.spec.SignPairGenSpec
import org.bouncycastle.kcrypto.spec.VerifyGenSpec
import java.security.SecureRandom

class DSAGenSpec(val domainParameters: DSADomainParameters, override val random: SecureRandom): SignPairGenSpec {
    constructor(domainParameters: DSADomainParameters) : this(domainParameters, KCryptoServices.secureRandom)

    override val signType get() = DSAGenSpec.signType
    override val verifyType get() = DSAGenSpec.verifyType

    companion object: SignGenSpec, VerifyGenSpec {
        override val signType = KeyType.SIGNING.forAlgorithm("DSA")
        override val verifyType = KeyType.VERIFICATION.forAlgorithm("DSA")
    }
}