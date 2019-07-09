package org.bouncycastle.kcrypto.spec.symmetric

import KCryptoServices
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.cms.GCMParameters
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.SymmetricKey
import org.bouncycastle.kcrypto.spec.AEADAlgSpec
import org.bouncycastle.kcrypto.spec.createAlgOID

/**
 * GCM Mode specification
 */
class GCMSpec : AEADAlgSpec<AlgorithmIdentifier> {

    val algorithm: ASN1ObjectIdentifier?
    val iv: ByteArray
    val tagSize: Int

    constructor() {
        var pGen = KCryptoServices.helper.createAlgorithmParameterGenerator("GCM")
        var params = GCMParameters.getInstance(pGen.generateParameters().encoded)

        this.algorithm = null
        this.iv = params.nonce;
        this.tagSize = params.icvLen * 8
    }

    private constructor(algorithm: ASN1ObjectIdentifier, iv: ByteArray, tagSize: Int) {
        this.algorithm = algorithm
        this.iv = iv;
        this.tagSize = tagSize
    }

    constructor(iv: ByteArray, tagSize: Int) {
        this.algorithm = null
        this.iv = iv
        this.tagSize = tagSize
    }

    constructor(algId: AlgorithmIdentifier) {
        var params = GCMParameters.getInstance(algId.parameters)

        this.algorithm = algId.algorithm
        this.iv = params.nonce
        this.tagSize = params.icvLen * 8
    }

    override val algorithmIdentifier: AlgorithmIdentifier
        get() = {
            if (algorithm == null) {
                throw IllegalStateException("spec not validated")
            }
            AlgorithmIdentifier(algorithm, GCMParameters(iv, (tagSize + 7) / 8))
        }.invoke()

    override fun validatedSpec(key: SymmetricKey): GCMSpec {
        val expectedOid = createAlgOID(key.size, this)

        if (algorithm == null) {
            return GCMSpec(expectedOid, this.iv, this.tagSize)
        }
        if (expectedOid.equals(algorithm)) {
            return this
        }

        throw IllegalStateException("key not matched to GCMSpec")
    }
}