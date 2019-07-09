package org.bouncycastle.kcrypto.spec.symmetric

import KCryptoServices
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.cms.CCMParameters
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.AuthenticationKey
import org.bouncycastle.kcrypto.SymmetricKey
import org.bouncycastle.kcrypto.spec.AEADAlgSpec
import org.bouncycastle.kcrypto.spec.MacAlgSpec
import org.bouncycastle.kcrypto.spec.createAlgOID

/**
 * CCM mode specification
 */
class CCMSpec : AEADAlgSpec<AlgorithmIdentifier>, MacAlgSpec<AlgorithmIdentifier> {

    val algorithm: ASN1ObjectIdentifier?
    val iv: ByteArray
    val tagSize: Int

    constructor() {
        var pGen = KCryptoServices.helper.createAlgorithmParameterGenerator("CCM")
        var params = CCMParameters.getInstance(pGen.generateParameters().encoded)

        this.algorithm = null
        this.iv = params.nonce;
        this.tagSize = params.icvLen * 8;
    }

    private constructor(algorithm: ASN1ObjectIdentifier, iv: ByteArray, tagSize: Int) {
        this.algorithm = algorithm
        this.iv = iv
        this.tagSize = tagSize
    }

    constructor(iv: ByteArray, tagSize: Int) {
        this.algorithm = null
        this.iv = iv
        this.tagSize = tagSize
    }

    constructor(parameters: ByteArray) {
        var params = CCMParameters.getInstance(parameters)

        this.algorithm = null
        this.iv = params.nonce
        this.tagSize = params.icvLen * 8
    }

    constructor(algId: AlgorithmIdentifier) {
        var params = CCMParameters.getInstance(algId.parameters)

        this.algorithm = algId.algorithm
        this.iv = params.nonce
        this.tagSize = params.icvLen * 8
    }

    override val algorithmIdentifier: AlgorithmIdentifier
        get() = {
            if (algorithm == null) {
                throw IllegalStateException("spec not validated")
            }
            AlgorithmIdentifier(algorithm, CCMParameters(iv, (tagSize + 7) / 8))
        }.invoke()

    override fun validatedSpec(key: SymmetricKey): CCMSpec {

        val expectedOid = createAlgOID(key.size, this)

        if (algorithm == null) {
            return CCMSpec(expectedOid, this.iv, this.tagSize)
        }
        if (expectedOid.equals(algorithm)) {
            return this
        }

        throw IllegalStateException("key not matched to CCMSpec")
    }

    override fun validatedSpec(key: AuthenticationKey): MacAlgSpec<AlgorithmIdentifier> {
        val expectedOid = createAlgOID(key.size, this)

        if (algorithm == null) {
            return CCMSpec(expectedOid, this.iv, this.tagSize)
        }
        if (expectedOid.equals(algorithm)) {
            return this
        }

        throw IllegalStateException("key not matched to CCMSpec")
    }
}