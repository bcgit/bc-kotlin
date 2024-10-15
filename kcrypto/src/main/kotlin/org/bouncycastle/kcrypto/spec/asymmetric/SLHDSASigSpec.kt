package org.bouncycastle.kcrypto.spec.asymmetric

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.jcajce.interfaces.SLHDSAKey
import org.bouncycastle.kcrypto.BaseSigningKey
import org.bouncycastle.kcrypto.BaseVerificationKey
import org.bouncycastle.kcrypto.SigningKey
import org.bouncycastle.kcrypto.VerificationKey
import org.bouncycastle.kcrypto.spec.SigAlgSpec

val slh_dsa_sha2_128f = NISTObjectIdentifiers.id_slh_dsa_sha2_128f
val slh_dsa_sha2_128s = NISTObjectIdentifiers.id_slh_dsa_sha2_128s
val slh_dsa_sha2_192f = NISTObjectIdentifiers.id_slh_dsa_sha2_192f
val slh_dsa_sha2_192s = NISTObjectIdentifiers.id_slh_dsa_sha2_192s
val slh_dsa_sha2_256f = NISTObjectIdentifiers.id_slh_dsa_sha2_256f
val slh_dsa_sha2_256s = NISTObjectIdentifiers.id_slh_dsa_sha2_256s
val slh_dsa_shake_128f = NISTObjectIdentifiers.id_slh_dsa_shake_128f
val slh_dsa_shake_128s = NISTObjectIdentifiers.id_slh_dsa_shake_128s
val slh_dsa_shake_192f = NISTObjectIdentifiers.id_slh_dsa_shake_192f
val slh_dsa_shake_192s = NISTObjectIdentifiers.id_slh_dsa_shake_192s
val slh_dsa_shake_256f = NISTObjectIdentifiers.id_slh_dsa_shake_256f
val slh_dsa_shake_256s = NISTObjectIdentifiers.id_slh_dsa_shake_256s

class SLHDSASigSpec: SigAlgSpec {

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

    override fun validatedSpec(key: VerificationKey): SLHDSASigSpec {

        if (algId == null) {
            if (key is BaseVerificationKey) {
                return SLHDSASigSpec(AlgorithmIdentifier(getSlhDsaOid((key._pubKey as SLHDSAKey).parameterSpec.name)))
            }
            throw IllegalStateException("unknown key")
        }

        return this
    }

    override fun validatedSpec(key: SigningKey): SLHDSASigSpec {


        
        if (algId == null) {
            if (key is BaseSigningKey) {
                return SLHDSASigSpec(AlgorithmIdentifier(getSlhDsaOid((key._privKey as SLHDSAKey).parameterSpec.name)))
            }
            throw IllegalStateException("unknown key")
        }

        return this
    }

    private fun getSlhDsaOid(name: String): ASN1ObjectIdentifier {
        if (name.equals("slh-dsa-shake-128f", true)) {
            return NISTObjectIdentifiers.id_slh_dsa_shake_128f
        } else if (name.equals("slh-dsa-shake-128s", true)) {
            return NISTObjectIdentifiers.id_slh_dsa_shake_128s
        } else if (name.equals("slh-dsa-shake-192f", true)) {
            return NISTObjectIdentifiers.id_slh_dsa_shake_192f
        } else if (name.equals("slh-dsa-shake-192s", true)) {
            return NISTObjectIdentifiers.id_slh_dsa_shake_192s
        } else if (name.equals("slh-dsa-shake-256f", true)) {
            return NISTObjectIdentifiers.id_slh_dsa_shake_256f
        } else if (name.equals("slh-dsa-shake-256s", true)) {
            return NISTObjectIdentifiers.id_slh_dsa_shake_256s
        } else if (name.equals("slh-dsa-sha2-128f", true)) {
            return NISTObjectIdentifiers.id_slh_dsa_sha2_128f
        } else if (name.equals("slh-dsa-sha2-128s", true)) {
            return NISTObjectIdentifiers.id_slh_dsa_sha2_128s
        } else if (name.equals("slh-dsa-sha2-192f", true)) {
            return NISTObjectIdentifiers.id_slh_dsa_sha2_192f
        } else if (name.equals("slh-dsa-sha2-192s", true)) {
            return NISTObjectIdentifiers.id_slh_dsa_shake_192s
        } else if (name.equals("slh-dsa-sha2-256f", true)) {
            return NISTObjectIdentifiers.id_slh_dsa_sha2_256f
        } else if (name.equals("slh-dsa-sha2-256s", true)) {
            return NISTObjectIdentifiers.id_slh_dsa_sha2_256s
        } else {
            throw IllegalArgumentException("unknown parameter set: " + name)
        }
    }
}