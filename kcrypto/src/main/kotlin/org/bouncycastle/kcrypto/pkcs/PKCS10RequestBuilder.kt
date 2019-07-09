package org.bouncycastle.kcrypto.pkcs

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.kcrypto.*
import org.bouncycastle.kcrypto.internal.KContentSigner
import org.bouncycastle.kcrypto.spec.SigAlgSpec
import org.bouncycastle.kcrypto.spec.asymmetric.PKCS1SigSpec
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder

/**
 * Builder for PKCS#10 certification requests.
 */
class PKCS10RequestBuilder(private val signatureCalculator: SignatureCalculator<AlgorithmIdentifier>, subjectName: X500Name, publicKeyInfo: SubjectPublicKeyInfo) {

    constructor(signatureCalculator: SignatureCalculator<AlgorithmIdentifier>, subjectName: X500Name, publicKey: VerificationKey): this(signatureCalculator, subjectName, SubjectPublicKeyInfo.getInstance(publicKey.encoding))

    /**
     * Create a PKCS#10 certification request builder based on this signing key for the passed in signature specification.
     *
     * @param signingKey the key to use to sign the request.
     * @param sigAlgSpec name of the signature algorithm to use for signing the PKCS#10 request.
     * @param subjectName the subject name to include in the PKCS#10 request.
     * @param publicKey the subject public key to include in the PKCS#10 request.
     */
    constructor(signingKey: SigningKey, sigAlgSpec: SigAlgSpec, subjectName: X500Name, publicKey: VerificationKey): this(signingKey.signatureCalculator(sigAlgSpec), subjectName, publicKey)

    constructor(signingKeyPair: SigningKeyPair, sigAlgSpec: PKCS1SigSpec, name: X500Name) : this(signingKeyPair.signingKey, sigAlgSpec, name, signingKeyPair.verificationKey)

    constructor(encryptionKeyPair: EncryptingKeyPair, sigAlgSpec: PKCS1SigSpec, name: X500Name) : this(SigningKeyPair(encryptionKeyPair.kp).signingKey.signatureCalculator(sigAlgSpec), name, SubjectPublicKeyInfo.getInstance(encryptionKeyPair.encryptionKey.encoding))
    
    val bldr = PKCS10CertificationRequestBuilder(subjectName, publicKeyInfo)

    /**
     * Add an attribute to the certification request we are building.
     *
     * @param attrType  the OID giving the type of the attribute.
     * @param attrValue the ASN.1 structure that forms the value of the attribute.
     * @return this builder object.
     */
    fun addAttribute(attrType: ASN1ObjectIdentifier, attrValue: ASN1Encodable): PKCS10RequestBuilder {
        bldr.addAttribute(attrType, attrValue)
        return this
    }

    /**
     * Add an attribute with multiple values to the certification request we are building.
     *
     * @param attrType   the OID giving the type of the attribute.
     * @param attrValues an array of ASN.1 structures that form the value of the attribute.
     * @return this builder object.
     */
    fun addAttribute(attrType: ASN1ObjectIdentifier, attrValues: Array<ASN1Encodable>): PKCS10RequestBuilder {
        bldr.addAttribute(attrType, attrValues)
        return this
    }

    /**
     * The attributes field in PKCS10 should encoded to an empty tagged set if there are
     * no attributes. Some CAs will reject requests with the attribute field present.
     *
     * @param leaveOffEmpty true if empty attributes should be left out of the encoding false otherwise.
     * @return this builder object.
     */
    fun setLeaveOffEmptyAttributes(leaveOffEmpty: Boolean): PKCS10RequestBuilder {
        bldr.setLeaveOffEmptyAttributes(leaveOffEmpty)
        return this
    }

    /**
     * Build the final PKCS#10 certification request.
     *
     * @return a PKCS#10 certification request.
     */
    fun build(): PKCS10Request {

        return PKCS10Request(bldr.build(KContentSigner(signatureCalculator)).encoded)
    }
}