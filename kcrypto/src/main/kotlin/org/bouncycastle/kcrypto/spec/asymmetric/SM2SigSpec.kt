package org.bouncycastle.kcrypto.spec.asymmetric

import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.Digest
import org.bouncycastle.kcrypto.ID
import org.bouncycastle.kcrypto.SigningKey
import org.bouncycastle.kcrypto.VerificationKey
import org.bouncycastle.kcrypto.spec.SigAlgSpec
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder

/**
 * SM2 signature specification
 */
class SM2SigSpec : SigAlgSpec {
    val id: ID?
    val digest: Digest
    private val algId: AlgorithmIdentifier?

    constructor(digest: Digest, id: ID?) {
        this.digest = digest
        this.id = id
        this.algId = null
    }

    internal constructor(digest: Digest, id: ID?, algorithmIdentifier: AlgorithmIdentifier) {
        this.digest = digest
        this.id = id
        this.algId = algorithmIdentifier
    }

    override val algorithmIdentifier: AlgorithmIdentifier
        get() = {
            if (algId != null) {
                algId
            } else {
                throw IllegalStateException("spec not validated")
            }
        }.invoke()

    override fun validatedSpec(key: VerificationKey): SM2SigSpec {

        if (algId == null) {
            return SM2SigSpec(digest, id, getAlgorithmIdentifier(digest))
        }

        return this
    }

    override fun validatedSpec(key: SigningKey): SM2SigSpec {

        if (algId == null) {
            return SM2SigSpec(digest, id, getAlgorithmIdentifier(digest))
        }

        return this
    }

    private fun getAlgorithmIdentifier(digest: Digest): AlgorithmIdentifier {
        return DefaultSignatureAlgorithmIdentifierFinder().find(simplify(digest.algorithmName) + "withSM2")
    }

    // TODO
    private fun simplify(algorithmName: String): String {
        return algorithmName.replace("-", "")
    }
}