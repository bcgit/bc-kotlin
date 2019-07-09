package org.bouncycastle.kcrypto.cms

import KCryptoServices
import org.bouncycastle.cert.X509AttributeCertificateHolder
import org.bouncycastle.cert.X509CRLHolder
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cms.*
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder
import org.bouncycastle.kcrypto.Encodable
import org.bouncycastle.kcrypto.cert.AttributeCertificate
import org.bouncycastle.kcrypto.cert.CRL
import org.bouncycastle.kcrypto.cert.Certificate
import org.bouncycastle.kutil.CollectionStore
import org.bouncycastle.kutil.Store
import java.io.InputStream


/**
 * general class for handling a pkcs7-signature message.
 *
 * A simple example of usage - note, in the example below the validity of
 * the certificate isn't verified, just the fact that one of the certs
 * matches the given signer...
 *
 * <pre>
 * val s: SignedData = ...
 * val certificates = s.certificates
 * var verifiedCount = 0
 *
 * for (signer in s.signerInfos) {
 *     var cert = certificates.match(signer.certificateID)
 *
 *     if (cert != null && signer.signatureVerifiedBy(cert)) {
 *         verifiedCount++
 *     }
 * }
 * </pre>
 */
class SignedData: Encodable {

    private val dataMessage: CMSSignedData

    constructor(inputStream: InputStream) {
        this.dataMessage = CMSSignedData(inputStream)
    }

    constructor(input: ByteArray) {
        this.dataMessage = CMSSignedData(input)
    }

    constructor(signedData: SignedData, msg: TypedContent) {
        this.dataMessage = CMSSignedData(CMSProcessableByteArray(msg.type, msg.content), signedData.encoding)
    }

    override val encoding: ByteArray get() = dataMessage.encoded

    val certificates: Store<Certificate> get() = CollectionStore(dataMessage.certificates.getMatches(null).map { Certificate((it as X509CertificateHolder).encoded) })
    val crls: Store<CRL> get() = CollectionStore(dataMessage.crLs.getMatches(null).map { CRL((it as X509CRLHolder).encoded) })
    val attributeCertificates: Store<AttributeCertificate> get() = CollectionStore(dataMessage.attributeCertificates.getMatches(null).map { AttributeCertificate((it as X509AttributeCertificateHolder).encoded) })
    val isCertificateManagementMessage: Boolean get() = dataMessage.isCertificateManagementMessage()

    val signedContent get() = if (dataMessage.signedContent != null) TypedByteArray(dataMessage.signedContent.contentType, dataMessage.signedContent.content as ByteArray) else null
    val signerInfos: Store<SignerInfo> get() = CollectionStore(dataMessage.signerInfos.signers.map { SignerInfo(it) })

    val digestAlgorithms
        get() = dataMessage.digestAlgorithmIDs.toSet()

    /**
     * Verify all the SignerInfo objects and their associated counter signatures attached
     * to this CMS SignedData object.
     *
     * @param verifierCerts  a Store of certificates representing all the signers in the SignedData.
     * @return true if all verify, false otherwise.
     */
    fun allSignaturesVerify(verifierCerts: Store<Certificate>): Boolean {
        return allSignaturesVerify(verifierCerts, false)
    }

    /**
     * Verify all the SignerInfo objects and their associated counter signatures attached
     * to this CMS SignedData object.
     *
     * @param verifierCerts  a Store of certificates representing all the signers in the SignedData.
     * @param ignoreCounterSignatures if true don't check counter signatures. If false check counter signatures as well.
     * @return true if all verify, false otherwise.
     */
    fun allSignaturesVerify(verifierCerts: Store<Certificate>, ignoreCounterSignatures: Boolean): Boolean {
        return dataMessage.verifySignatures(DKSignerInformationVerifierProvider(verifierCerts), ignoreCounterSignatures)
    }

    /**
     * Create a new SignedData object replacing the current store of SignerInfo objects with the passed in one.
     *
     * @param signers the new SignerInfo objects to use.
     */
    fun withSigners(signers: Store<SignerInfo>): SignedData
    {
        val siStore = SignerInformationStore(signers.map { it.signerInf })

        return SignedData(CMSSignedData.replaceSigners(dataMessage, siStore).encoded)
    }

    /**
     * Create a new SignedData object replacing the current store of certificates, attrCerts, and/or crl objects with the passed in ones.
     *
     * @param certificates a Store of replacement certificates (if null no certificates will be included)
     * @param attrCerts a Store of replacement attribute certificates (if null no attribute certificates will be included)
     * @param crls a Store of replacement CRLs (if null no CRLs will be included)
     */
    fun withCertificatesAndCRLs(certificates: Store<Certificate>?, attrCerts: Store<AttributeCertificate>?, crls: Store<CRL>?): SignedData
    {
        val cStore = if (certificates != null) org.bouncycastle.util.CollectionStore(certificates.map { it._cert }) else null
        val aStore = if (attrCerts != null) org.bouncycastle.util.CollectionStore(attrCerts.map { it._cert }) else null
        val crlStore = if (crls != null) org.bouncycastle.util.CollectionStore(crls.map { it._crl }) else null

        return SignedData(CMSSignedData.replaceCertificatesAndCRLs(dataMessage, cStore, aStore, crlStore).encoded)
    }
}

private class DKSignerInformationVerifierProvider(private val verifierCerts: Store<Certificate>) : SignerInformationVerifierProvider {
    override fun get(sid: SignerId): SignerInformationVerifier {

        val cert = verifierCerts.match(KSidCert(sid))
        if (cert != null) {
            return JcaSimpleSignerInfoVerifierBuilder().setProvider(KCryptoServices._provider).build(cert._cert)
        }
        throw IllegalStateException("no verifier certificate found for SignerInfo")
    }
}