package org.bouncycastle.kcrypto.spec.asymmetric

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.BaseSigningKey
import org.bouncycastle.kcrypto.BaseVerificationKey
import org.bouncycastle.kcrypto.SigningKey
import org.bouncycastle.kcrypto.VerificationKey
import org.bouncycastle.kcrypto.spec.SigAlgSpec

// these are only in 1.0.2
private val id_Ed25519 = ASN1ObjectIdentifier("1.3.101").branch("112").intern()
private val id_Ed448 = ASN1ObjectIdentifier("1.3.101").branch("113").intern()

class EdDSASigSpec: SigAlgSpec {

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

    override fun validatedSpec(key: VerificationKey): EdDSASigSpec {

        if (algId == null) {
            if (key is BaseVerificationKey) {
                if (key._pubKey.algorithm.endsWith("448")) {
                    return EdDSASigSpec(AlgorithmIdentifier(id_Ed448))
                } else {
                    return EdDSASigSpec(AlgorithmIdentifier(id_Ed25519))
                }
            }
            throw IllegalStateException("unknown key")
        }

        return this
    }

    override fun validatedSpec(key: SigningKey): EdDSASigSpec {

        if (algId == null) {
            if (key is BaseSigningKey) {
                if (key._privKey.algorithm.endsWith("448")) {
                    return EdDSASigSpec(AlgorithmIdentifier(id_Ed448))
                } else {
                    return EdDSASigSpec(AlgorithmIdentifier(id_Ed25519))
                }
            }
            throw IllegalStateException("unknown key")
        }

        return this
    }
}