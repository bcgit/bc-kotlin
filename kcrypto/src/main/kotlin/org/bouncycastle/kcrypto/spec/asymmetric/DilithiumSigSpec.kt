package org.bouncycastle.kcrypto.spec.asymmetric

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.BaseSigningKey
import org.bouncycastle.kcrypto.BaseVerificationKey
import org.bouncycastle.kcrypto.SigningKey
import org.bouncycastle.kcrypto.VerificationKey
import org.bouncycastle.kcrypto.spec.SigAlgSpec
import org.bouncycastle.pqc.jcajce.interfaces.DilithiumKey
import org.bouncycastle.pqc.jcajce.interfaces.FalconKey
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec

// these are only in 1.0.2
// OpenSSL OIDs
val dilithium2 = ASN1ObjectIdentifier("1.3.6.1.4.1.2.267.7.4.4") // dilithium.branch("1");
val dilithium3 = ASN1ObjectIdentifier("1.3.6.1.4.1.2.267.7.6.5") // dilithium.branch("2");
val dilithium5 = ASN1ObjectIdentifier("1.3.6.1.4.1.2.267.7.8.7") // dilithium.branch("3");


class DilithiumSigSpec: SigAlgSpec {

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

    override fun validatedSpec(key: VerificationKey): DilithiumSigSpec {

        if (algId == null) {
            if (key is BaseVerificationKey) {
                return dilithiumSigSpec((key._pubKey as DilithiumKey).parameterSpec)
            }
            throw IllegalStateException("unknown key")
        }

        return this
    }

    override fun validatedSpec(key: SigningKey): DilithiumSigSpec {

        if (algId == null) {
            if (key is BaseSigningKey) {
                return dilithiumSigSpec((key._privKey as DilithiumKey).parameterSpec)
            }
            throw IllegalStateException("unknown key")
        }

        return this
    }

    private fun dilithiumSigSpec(parameterSpec: DilithiumParameterSpec?): DilithiumSigSpec {
        if (parameterSpec == DilithiumParameterSpec.dilithium2) {
            return DilithiumSigSpec(AlgorithmIdentifier(dilithium2))
        } else if (parameterSpec == DilithiumParameterSpec.dilithium3) {
            return DilithiumSigSpec(AlgorithmIdentifier(dilithium3))
        } else {
            return DilithiumSigSpec(AlgorithmIdentifier(dilithium5))
        }
    }
}