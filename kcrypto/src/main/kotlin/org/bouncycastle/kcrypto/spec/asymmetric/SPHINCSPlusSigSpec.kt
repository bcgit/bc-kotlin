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
val sphincsPlus = BCObjectIdentifiers.sphincsPlus_interop

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
        if (name.equals("shake-128f")) {
            return BCObjectIdentifiers.sphincsPlus_shake_128f
        } else if (name.equals("shake-128s")) {
            return BCObjectIdentifiers.sphincsPlus_shake_128s
        } else if (name.equals("shake-192f")) {
            return BCObjectIdentifiers.sphincsPlus_shake_192f
        } else if (name.equals("shake-192s")) {
            return BCObjectIdentifiers.sphincsPlus_shake_192s
        } else if (name.equals("shake-256f")) {
            return BCObjectIdentifiers.sphincsPlus_shake_256f
        } else if (name.equals("shake-256s")) {
            return BCObjectIdentifiers.sphincsPlus_shake_256s
        } else if (name.equals("sha2-128f")) {
            return BCObjectIdentifiers.sphincsPlus_sha2_128f
        } else if (name.equals("sha2-128s")) {
            return BCObjectIdentifiers.sphincsPlus_sha2_128s
        } else if (name.equals("sha2-192f")) {
            return BCObjectIdentifiers.sphincsPlus_sha2_192f
        } else if (name.equals("sha2-192s")) {
            return BCObjectIdentifiers.sphincsPlus_sha2_192s
        } else if (name.equals("sha2-256f")) {
            return BCObjectIdentifiers.sphincsPlus_sha2_256f
        } else if (name.equals("sha2-256s")) {
            return BCObjectIdentifiers.sphincsPlus_sha2_256s
        } else {
            throw IllegalArgumentException("unknown parameter set: " + name)
        }
    }
}