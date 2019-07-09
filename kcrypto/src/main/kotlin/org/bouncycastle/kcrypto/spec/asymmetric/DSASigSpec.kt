package org.bouncycastle.kcrypto.spec.asymmetric

import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.Digest
import org.bouncycastle.kcrypto.SigningKey
import org.bouncycastle.kcrypto.VerificationKey
import org.bouncycastle.kcrypto.spec.SigAlgSpec
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder

class DSASigSpec: SigAlgSpec {

    val digest: Digest

    private val algId: AlgorithmIdentifier?

    constructor(digest: Digest)
    {
        this.digest = digest
        this.algId = null
    }

    internal constructor(digest: Digest, algorithmIdentifier: AlgorithmIdentifier)
    {
        this.digest = digest
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

    override fun validatedSpec(key: VerificationKey): DSASigSpec {

        if (algId == null) {
            return DSASigSpec(digest, getAlgorithmIdentifier(digest))
        }

        return this
    }

    override fun validatedSpec(key: SigningKey): DSASigSpec {

        if (algId == null) {
            return DSASigSpec(digest, getAlgorithmIdentifier(digest))
        }

        return this
    }

    private fun getAlgorithmIdentifier(digest: Digest): AlgorithmIdentifier
    {
         return DefaultSignatureAlgorithmIdentifierFinder().find(simplify(digest.algorithmName) + "withDSA")
    }

    // TODO
    private fun simplify(algorithmName: String): String {
        return algorithmName.replace("-", "")
    }

}