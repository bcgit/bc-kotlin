package org.bouncycastle.kcrypto.spec.symmetric

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.SymmetricKey
import org.bouncycastle.kcrypto.spec.SymAlgSpec
import org.bouncycastle.kcrypto.spec.createAlgOID


/**
 * Key Wrapping mode specification.
 */
class KWPSpec : SymAlgSpec<AlgorithmIdentifier> {

    private val algorithm: ASN1ObjectIdentifier?

    constructor() {
        this.algorithm = null;
    }

    constructor(algorithmIdentifier: AlgorithmIdentifier) {
        this.algorithm = algorithmIdentifier.algorithm;
    }

    private constructor(algorithm: ASN1ObjectIdentifier) {
        this.algorithm = algorithm;
    }

    override val algorithmIdentifier: AlgorithmIdentifier
        get() = {
            if (algorithm == null) {
                throw IllegalStateException("spec not validated")
            }
            AlgorithmIdentifier(algorithm)
        }.invoke()

    override fun validatedSpec(key: SymmetricKey): KWPSpec {
        val expectedOid = createAlgOID(key.size, this)

        if (algorithm == null) {
            return KWPSpec(expectedOid)
        }
        if (expectedOid.equals(algorithm)) {
            return this
        }

        throw IllegalStateException("key not matched to KWPSpec")
    }

}