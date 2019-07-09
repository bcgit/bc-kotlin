package org.bouncycastle.kcrypto.spec.symmetric

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.AuthenticationKey
import org.bouncycastle.kcrypto.spec.MacAlgSpec

class CMACSpec: MacAlgSpec<AlgorithmIdentifier> {

    val algorithm: ASN1ObjectIdentifier?

    constructor()
    {
        algorithm = null;
    }

    override val algorithmIdentifier: AlgorithmIdentifier
        get() = {
            if (algorithm == null) {
                throw IllegalStateException("spec not validated")
            }
            AlgorithmIdentifier(algorithm, DERNull.INSTANCE)
        }.invoke()

    override fun validatedSpec(key: AuthenticationKey): MacAlgSpec<AlgorithmIdentifier> {
        throw IllegalStateException("no algorithm identifier available")
    }
}