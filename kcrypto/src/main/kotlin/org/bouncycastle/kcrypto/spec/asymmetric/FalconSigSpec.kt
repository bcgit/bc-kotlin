package org.bouncycastle.kcrypto.spec.asymmetric

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.bc.BCObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.BaseSigningKey
import org.bouncycastle.kcrypto.BaseVerificationKey
import org.bouncycastle.kcrypto.SigningKey
import org.bouncycastle.kcrypto.VerificationKey
import org.bouncycastle.kcrypto.spec.SigAlgSpec
import org.bouncycastle.pqc.jcajce.interfaces.FalconKey
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec

// these are only in 1.0.2
private val falcon_512 = ASN1ObjectIdentifier("1.3.9999.3.1") // falcon.branch("1");
private val falcon_1024 = ASN1ObjectIdentifier("1.3.9999.3.4") // falcon.branch("2");


class FalconSigSpec: SigAlgSpec {

    private val algId: AlgorithmIdentifier?

    constructor()
    {
        this.algId = null
    }

    internal constructor(algorithmIdentifier: AlgorithmIdentifier)
    {
        this.algId = algorithmIdentifier
    }

    override val algorithmIdentifier: AlgorithmIdentifier
        get() = {
            if (algId != null) {
                algId
            }
            else
            {
                throw IllegalStateException("spec not validated")
            }
        }.invoke()

    override fun validatedSpec(key: VerificationKey): FalconSigSpec {

        if (algId == null) {
            if (key is BaseVerificationKey) {
                if ((key._pubKey as FalconKey).parameterSpec == FalconParameterSpec.falcon_512) {
                    return FalconSigSpec(AlgorithmIdentifier(falcon_512))
                } else {
                    return FalconSigSpec(AlgorithmIdentifier(falcon_1024))
                }
            }
            throw IllegalStateException("unknown key")
        }

        return this
    }

    override fun validatedSpec(key: SigningKey): FalconSigSpec {

        if (algId == null) {
            if (key is BaseSigningKey) {
                if ((key._privKey as FalconKey).parameterSpec == FalconParameterSpec.falcon_512) {
                    return FalconSigSpec(AlgorithmIdentifier(falcon_512))
                } else {
                    return FalconSigSpec(AlgorithmIdentifier(falcon_1024))
                }
            }
            throw IllegalStateException("unknown key")
        }

        return this
    }
}