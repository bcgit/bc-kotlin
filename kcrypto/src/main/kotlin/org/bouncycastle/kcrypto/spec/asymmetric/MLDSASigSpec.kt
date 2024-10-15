package org.bouncycastle.kcrypto.spec.asymmetric

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.jcajce.interfaces.MLDSAKey
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec
import org.bouncycastle.kcrypto.BaseSigningKey
import org.bouncycastle.kcrypto.BaseVerificationKey
import org.bouncycastle.kcrypto.SigningKey
import org.bouncycastle.kcrypto.VerificationKey
import org.bouncycastle.kcrypto.spec.SigAlgSpec

val ml_dsa_44 = NISTObjectIdentifiers.id_ml_dsa_44
val ml_dsa_65 = NISTObjectIdentifiers.id_ml_dsa_65
val ml_dsa_87 = NISTObjectIdentifiers.id_ml_dsa_87
val ml_dsa_44_with_sha512 = NISTObjectIdentifiers.id_hash_ml_dsa_44_with_sha512
val ml_dsa_65_with_sha512 = NISTObjectIdentifiers.id_hash_ml_dsa_65_with_sha512
val ml_dsa_87_with_sha512 = NISTObjectIdentifiers.id_hash_ml_dsa_87_with_sha512

class MLDSASigSpec: SigAlgSpec {

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

    override fun validatedSpec(key: VerificationKey): MLDSASigSpec {

        if (algId == null) {
            if (key is BaseVerificationKey) {
                return mldsaSigSpec((key._pubKey as MLDSAKey).parameterSpec)
            }
            throw IllegalStateException("unknown key")
        }

        return this
    }

    override fun validatedSpec(key: SigningKey): MLDSASigSpec {

        if (algId == null) {
            if (key is BaseSigningKey) {
                return mldsaSigSpec((key._privKey as MLDSAKey).parameterSpec)
            }
            throw IllegalStateException("unknown key")
        }

        return this
    }

    private fun mldsaSigSpec(parameterSpec: MLDSAParameterSpec?): MLDSASigSpec {
        if (parameterSpec == MLDSAParameterSpec.ml_dsa_44) {
            return MLDSASigSpec(AlgorithmIdentifier(ml_dsa_44))
        } else if (parameterSpec == MLDSAParameterSpec.ml_dsa_65) {
            return MLDSASigSpec(AlgorithmIdentifier(ml_dsa_65))
        } else if (parameterSpec == MLDSAParameterSpec.ml_dsa_87) {
            return MLDSASigSpec(AlgorithmIdentifier(ml_dsa_87))
        } else if (parameterSpec == MLDSAParameterSpec.ml_dsa_44_with_sha512) {
            return MLDSASigSpec(AlgorithmIdentifier(ml_dsa_44_with_sha512))
        } else if (parameterSpec == MLDSAParameterSpec.ml_dsa_65_with_sha512) {
            return MLDSASigSpec(AlgorithmIdentifier(ml_dsa_65_with_sha512))
        } else {
            return MLDSASigSpec(AlgorithmIdentifier(ml_dsa_87_with_sha512))
        }
    }
}