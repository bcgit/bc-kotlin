package org.bouncycastle.kcrypto.spec.asymmetric

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.bc.BCObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.BaseSigningKey
import org.bouncycastle.kcrypto.BaseVerificationKey
import org.bouncycastle.kcrypto.SigningKey
import org.bouncycastle.kcrypto.VerificationKey
import org.bouncycastle.kcrypto.spec.SigAlgSpec
import org.bouncycastle.pqc.jcajce.interfaces.MayoKey

class MayoSigSpec: SigAlgSpec {

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

    override fun validatedSpec(key: VerificationKey): MayoSigSpec {

        if (algId == null) {
            if (key is BaseVerificationKey) {
                return MayoSigSpec(AlgorithmIdentifier(getMayoOID((key._pubKey as MayoKey))))
            }
            throw IllegalStateException("unknown key")
        }

        return this
    }

    override fun validatedSpec(key: SigningKey): MayoSigSpec {

        if (algId == null) {
            if (key is BaseSigningKey) {
                return MayoSigSpec(AlgorithmIdentifier(getMayoOID((key._privKey as MayoKey))))
            }
            throw IllegalStateException("unknown key")
        }

        return this
    }

    private fun getMayoOID(key: MayoKey): ASN1ObjectIdentifier {
        if (key.algorithm.equals("MAYO-1")) {
            return BCObjectIdentifiers.mayo1
        }
        if (key.algorithm.equals("MAYO-2")) {
            return BCObjectIdentifiers.mayo2
        }
        if (key.algorithm.equals("MAYO-3")) {
            return BCObjectIdentifiers.mayo3
        }
        if (key.algorithm.equals("MAYO-5")) {
            return BCObjectIdentifiers.mayo5
        }
        throw IllegalStateException("unknown key")
    }
}