package org.bouncycastle.kcrypto.spec.symmetric

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.AuthenticationKey
import org.bouncycastle.kcrypto.BaseHMacKey
import org.bouncycastle.kcrypto.spec.MacAlgSpec
import org.bouncycastle.kcrypto.spec.kdf.findPrfAlgId

class HMacSpec: MacAlgSpec<AlgorithmIdentifier> {

    val algorithm: ASN1ObjectIdentifier?

    constructor()
    {
        algorithm = null;
    }

    constructor(algorithmIdentifier: AlgorithmIdentifier)
    {
        algorithm = algorithmIdentifier.algorithm;
    }

    override val algorithmIdentifier: AlgorithmIdentifier
        get() = {
            if (algorithm == null) {
                throw IllegalStateException("spec not validated")
            }
            AlgorithmIdentifier(algorithm, DERNull.INSTANCE)
        }.invoke()

    override fun validatedSpec(key: AuthenticationKey): MacAlgSpec<AlgorithmIdentifier> {
        if (key is BaseHMacKey) {
            return HMacSpec(findPrfAlgId(key.prfType))
        }
        throw IllegalArgumentException("not HMAC key")
    }
}