package org.bouncycastle.kcrypto.spec.asymmetric

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.BaseSigningKey
import org.bouncycastle.kcrypto.BaseVerificationKey
import org.bouncycastle.kcrypto.SigningKey
import org.bouncycastle.kcrypto.VerificationKey
import org.bouncycastle.kcrypto.spec.SigAlgSpec
import org.bouncycastle.pqc.jcajce.interfaces.LMSKey

// these are only in 1.0.2
val lms = PKCSObjectIdentifiers.id_alg_hss_lms_hashsig

class LMSSigSpec: SigAlgSpec {

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

    override fun validatedSpec(key: VerificationKey): LMSSigSpec {

        if (algId == null) {
            if (key is BaseVerificationKey) {
                return LMSSigSpec(AlgorithmIdentifier(getLMSOID((key._pubKey as LMSKey))))
            }
            throw IllegalStateException("unknown key")
        }

        return this
    }

    override fun validatedSpec(key: SigningKey): LMSSigSpec {

        if (algId == null) {
            if (key is BaseSigningKey) {
                return LMSSigSpec(AlgorithmIdentifier(getLMSOID((key._privKey as LMSKey))))
            }
            throw IllegalStateException("unknown key")
        }

        return this
    }

    private fun getLMSOID(key: LMSKey): ASN1ObjectIdentifier {
        return PKCSObjectIdentifiers.id_alg_hss_lms_hashsig
    }
}