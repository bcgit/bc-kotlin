package org.bouncycastle.kcrypto.spec.asymmetric

import org.bouncycastle.asn1.bc.BCObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.BaseSigningKey
import org.bouncycastle.kcrypto.BaseVerificationKey
import org.bouncycastle.kcrypto.SigningKey
import org.bouncycastle.kcrypto.VerificationKey
import org.bouncycastle.kcrypto.spec.SigAlgSpec
import org.bouncycastle.pqc.jcajce.interfaces.DilithiumKey
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec

// these are only in 1.0.2
// OpenSSL OIDs
val dilithium2 = BCObjectIdentifiers.dilithium2 // dilithium.branch("1");
val dilithium3 = BCObjectIdentifiers.dilithium3 // dilithium.branch("2");
val dilithium5 = BCObjectIdentifiers.dilithium5 // dilithium.branch("3");


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