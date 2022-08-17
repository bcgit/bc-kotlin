package org.bouncycastle.kcrypto.spec.asymmetric

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.bc.BCObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.BaseSigningKey
import org.bouncycastle.kcrypto.BaseVerificationKey
import org.bouncycastle.kcrypto.SigningKey
import org.bouncycastle.kcrypto.VerificationKey
import org.bouncycastle.kcrypto.spec.SigAlgSpec
import org.bouncycastle.pqc.jcajce.interfaces.SPHINCSPlusKey

// these are only in 1.0.2
val sphincsPlus = BCObjectIdentifiers.sphincsPlus

class SPHINCSPlusSigSpec: SigAlgSpec {

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

    override fun validatedSpec(key: VerificationKey): SPHINCSPlusSigSpec {

        if (algId == null) {
            if (key is BaseVerificationKey) {
                return SPHINCSPlusSigSpec(AlgorithmIdentifier(getSphincsPlusOID((key._pubKey as SPHINCSPlusKey).parameterSpec.name)))
            }
            throw IllegalStateException("unknown key")
        }

        return this
    }

    override fun validatedSpec(key: SigningKey): SPHINCSPlusSigSpec {

        if (algId == null) {
            if (key is BaseSigningKey) {
                return SPHINCSPlusSigSpec(AlgorithmIdentifier(getSphincsPlusOID((key._privKey as SPHINCSPlusKey).parameterSpec.name)))
            }
            throw IllegalStateException("unknown key")
        }

        return this
    }

    private fun getSphincsPlusOID(name: String): ASN1ObjectIdentifier {
        return BCObjectIdentifiers.sphincsPlus
    }
}