package org.bouncycastle.kcrypto.crmf

import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.crmf.*
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.CertIOException
import org.bouncycastle.cert.crmf.*
import org.bouncycastle.operator.ContentSigner
import java.lang.IllegalArgumentException
import java.math.BigInteger
import java.util.*


/**
 * Builder for high-level objects built on [org.bouncycastle.asn1.crmf.CertReqMsg].
 */
class CertificateRequestBuilder(certReqId: BigInteger) {
    private val certReqMsgBldr: org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder = org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder(certReqId)

    fun setRegInfo(regInfo: Array<AttributeTypeAndValue>?): CertificateRequestBuilder {
        certReqMsgBldr.setRegInfo(regInfo)

        return this
    }

    fun setPublicKey(publicKey: SubjectPublicKeyInfo?): CertificateRequestBuilder {
        certReqMsgBldr.setPublicKey(publicKey)
        return this
    }

    fun setIssuer(issuer: X500Name?): CertificateRequestBuilder {
        certReqMsgBldr.setIssuer(issuer)
        return this
    }

    fun setSubject(subject: X500Name?): CertificateRequestBuilder {
        certReqMsgBldr.setSubject(subject)
        return this
    }

    fun setSerialNumber(serialNumber: BigInteger?): CertificateRequestBuilder {
        certReqMsgBldr.setSerialNumber(serialNumber)
        return this
    }

    /**
     * Request a validity period for the certificate. Either, but not both, of the date parameters may be null.
     *
     * @param notBeforeDate not before date for certificate requested.
     * @param notAfterDate  not after date for the certificate requested.
     * @return the current builder.
     */
    fun setValidity(notBeforeDate: Date?, notAfterDate: Date?): CertificateRequestBuilder {
        certReqMsgBldr.setValidity(notBeforeDate, notAfterDate)
        return this
    }

    fun addExtension(
        oid: ASN1ObjectIdentifier?,
        critical: Boolean,
        value: ASN1Encodable?
    ): CertificateRequestBuilder {
        try {
            certReqMsgBldr.addExtension(oid, critical, value)
        } catch (e: CertIOException) {
            throw IllegalArgumentException(e.message, e)
        }

        return this
    }

    fun addExtension(
        oid: ASN1ObjectIdentifier?,
        critical: Boolean,
        value: ByteArray?
    ): CertificateRequestBuilder {
        certReqMsgBldr.addExtension(oid, critical, value)
        return this
    }

    fun addControl(control: Control?): CertificateRequestBuilder {
        certReqMsgBldr.addControl(control)
        return this
    }

    fun setProofOfPossessionSigningKeySigner(popSigner: ContentSigner?): CertificateRequestBuilder {
        certReqMsgBldr.setProofOfPossessionSigningKeySigner(popSigner)
        return this
    }

    fun setProofOfPossessionSubsequentMessage(msg: SubsequentMessage?): CertificateRequestBuilder {
        certReqMsgBldr.setProofOfPossessionSubsequentMessage(msg)
        return this
    }

    fun setProofOfPossessionSubsequentMessage(type: Int, msg: SubsequentMessage?): CertificateRequestBuilder {
        certReqMsgBldr.setProofOfPossessionSubsequentMessage(type, msg)
        return this
    }

    fun setProofOfPossessionAgreeMAC(macValue: PKMACValue?): CertificateRequestBuilder {
        certReqMsgBldr.setProofOfPossessionAgreeMAC(macValue)
        return this
    }

    fun setProofOfPossessionRaVerified(): CertificateRequestBuilder {
        certReqMsgBldr.setProofOfPossessionRaVerified()
        return this
    }

    fun setAuthInfoPKMAC(pkmacBuilder: PKMACBuilder?, password: CharArray): CertificateRequestBuilder {
        certReqMsgBldr.setAuthInfoPKMAC(pkmacBuilder, password)
        return this
    }

    fun setAuthInfoSender(sender: X500Name?): CertificateRequestBuilder {
        return setAuthInfoSender(GeneralName(sender))
    }

    fun setAuthInfoSender(sender: GeneralName?): CertificateRequestBuilder {
        certReqMsgBldr.setAuthInfoSender(sender)
        return this
    }

    @Throws(CRMFException::class)
    fun build(): CertificateRequest {
        return CertificateRequest(certReqMsgBldr.build())
    }
}