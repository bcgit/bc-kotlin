package org.bouncycastle.kcrypto.cert

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.Extensions
import org.bouncycastle.asn1.x509.Time
import org.bouncycastle.cert.X509v2CRLBuilder
import org.bouncycastle.kcrypto.SignatureCalculator
import org.bouncycastle.kcrypto.SigningKey
import org.bouncycastle.kcrypto.internal.KContentSigner
import org.bouncycastle.kcrypto.spec.SigAlgSpec
import java.math.BigInteger
import java.util.*

/**
 * class to produce an X.509 Version 2 CRL.
 */
open class V2CRLBuilder {

    private var crlBuilder: X509v2CRLBuilder

    /**
     * Basic constructor.
     *
     * @param issuer the issuer this CRL is associated with.
     * @param thisUpdate  the date of this update.
     */
    constructor(
            issuer: X500Name,
            thisUpdate: Date) {
        crlBuilder = X509v2CRLBuilder(issuer, thisUpdate)
    }

    /**
     * Basic constructor.
     *
     * @param issuer the issuer this CRL is associated with.
     * @param thisUpdate  the Time of this update.
     */
    constructor(
            issuer: X500Name,
            thisUpdate: Time) {
        crlBuilder = X509v2CRLBuilder(issuer, thisUpdate)
    }

    /**
     * Basic constructor.
     *
     * @param issuerCert the issuer certificate this CRL is associated with.
     * @param thisUpdate  the Time of this update.
     */
    constructor(
            issuerCert: Certificate,
            thisUpdate: Time) {
        crlBuilder = X509v2CRLBuilder(issuerCert.subject, thisUpdate)
    }

    /**
     * Create a builder for a version 2 CRL, initialised with another CRL.
     *
     * @param templateCRL template CRL to base the new one on.
     */
    constructor(templateCRL: CRL) {
        crlBuilder = X509v2CRLBuilder(templateCRL._crl)
    }

    /**
     * Return if the extension indicated by OID is present.
     *
     * @param oid the OID for the extension of interest.
     * @return the Extension, or null if it is not present.
     */
    fun hasExtension(oid: ASN1ObjectIdentifier): Boolean {
        return crlBuilder.hasExtension(oid)
    }

    /**
     * Return the current value of the extension for OID.
     *
     * @param oid the OID for the extension we want to fetch.
     * @return true if a matching extension is present, false otherwise.
     */
    fun getExtension(oid: ASN1ObjectIdentifier): Extension? {
        return crlBuilder.getExtension(oid)
    }

    /**
     * Set the date by which the next CRL will become available.
     *
     * @param date  date of next CRL update.
     * @return the current builder.
     */
    fun setNextUpdate(date: Date): V2CRLBuilder {
        crlBuilder.setNextUpdate(date)

        return this
    }

    /**
     * Set the date by which the next CRL will become available.
     *
     * @param date  date of next CRL update.
     * @return the current builder.
     */
    fun setNextUpdate(date: Time): V2CRLBuilder {
        crlBuilder.setNextUpdate(date)

        return this
    }

    /**
     * Add a CRL entry with the just reasonCode extension.
     *
     * @param userCertificateSerial serial number of revoked certificate.
     * @param revocationDate date of certificate revocation.
     * @param reason the reason code, as indicated in CRLReason, i.e CRLReason.keyCompromise, or 0 if not to be used.
     * @return the current builder.
     */
    fun addCRLEntry(userCertificateSerial: BigInteger, revocationDate: Date, reason: RevocationReason): V2CRLBuilder {
        crlBuilder.addCRLEntry(userCertificateSerial, revocationDate, reason.value)

        return this
    }

    /**
     * Add a CRL entry with an invalidityDate extension as well as a reasonCode extension. This is used
     * where the date of revocation might be after issues with the certificate may have occurred.
     *
     * @param userCertificateSerial serial number of revoked certificate.
     * @param revocationDate date of certificate revocation.
     * @param reason the reason code, as indicated in CRLReason, i.e CRLReason.keyCompromise, or 0 if not to be used.
     * @param invalidityDate the date on which the private key for the certificate became compromised or the certificate otherwise became invalid.
     * @return the current builder.
     */
    fun addCRLEntry(userCertificateSerial: BigInteger, revocationDate: Date, reason: RevocationReason, invalidityDate: Date): V2CRLBuilder {
        crlBuilder.addCRLEntry(userCertificateSerial, revocationDate, reason.value, invalidityDate)

        return this
    }

    /**
     * Add a CRL entry with extensions.
     *
     * @param userCertificateSerial serial number of revoked certificate.
     * @param revocationDate date of certificate revocation.
     * @param extensions extension set to be associated with this CRLEntry.
     * @return the current builder.
     */
    fun addCRLEntry(userCertificateSerial: BigInteger, revocationDate: Date, extensions: Extensions): V2CRLBuilder {
        crlBuilder.addCRLEntry(userCertificateSerial, revocationDate, extensions)

        return this
    }

    /**
     * Add the CRLEntry objects contained in a previous CRL.
     *
     * @param other the X509CRLHolder to source the other entries from.
     * @return the current builder.
     */
    fun addCRL(other: CRL): V2CRLBuilder {

        crlBuilder.addCRL(other._crl)

        return this
    }

    /**
     * Add a given extension field for the standard extensions tag (tag 3)
     *
     * @param oid the OID defining the extension type.
     * @param isCritical true if the extension is critical, false otherwise.
     * @param value the ASN.1 structure that forms the extension's value.
     * @return this builder object.
     */
    fun addExtension(
            oid: ASN1ObjectIdentifier,
            isCritical: Boolean,
            value: ASN1Encodable): V2CRLBuilder {
        crlBuilder.addExtension(oid, isCritical, value)

        return this
    }

    /**
     * Add a given extension field for the standard extensions tag (tag 3) using a byte encoding of the
     * extension value.
     *
     * @param oid the OID defining the extension type.
     * @param isCritical true if the extension is critical, false otherwise.
     * @param encodedValue a byte array representing the encoding of the extension value.
     * @return this builder object.
     */
    fun addExtension(
            oid: ASN1ObjectIdentifier,
            isCritical: Boolean,
            encodedValue: ByteArray): V2CRLBuilder {
        crlBuilder.addExtension(oid, isCritical, encodedValue)

        return this
    }

    /**
     * Add a given extension field for the standard extensions tag (tag 3).
     *
     * @param extension the full extension value.
     * @return this builder object.
     */
    fun addExtension(
            extension: Extension): V2CRLBuilder {
        crlBuilder.addExtension(extension)

        return this
    }

    /**
     * Replace the extension field for the passed in extension's extension ID
     * with a new version.
     *
     * @param oid the OID defining the extension type.
     * @param isCritical true if the extension is critical, false otherwise.
     * @param value the ASN.1 structure that forms the extension's value.
     * @return this builder object.
     */
    fun replaceExtension(
            oid: ASN1ObjectIdentifier,
            isCritical: Boolean,
            value: ASN1Encodable): V2CRLBuilder {
        crlBuilder.replaceExtension(oid, isCritical, value)

        return this
    }

    /**
     * Replace the extension field for the passed in extension's extension ID
     * with a new version.
     *
     * @param extension the full extension value.
     * @return this builder object.
     */
    fun replaceExtension(
            extension: Extension): V2CRLBuilder {
        crlBuilder.replaceExtension(extension)

        return this
    }

    /**
     * Replace a given extension field for the standard extensions tag (tag 3) with the passed in
     * byte encoded extension value.
     *
     * @param oid the OID defining the extension type.
     * @param isCritical true if the extension is critical, false otherwise.
     * @param encodedValue a byte array representing the encoding of the extension value.
     * @return this builder object.
     */
    fun replaceExtension(
            oid: ASN1ObjectIdentifier,
            isCritical: Boolean,
            encodedValue: ByteArray): V2CRLBuilder {
        crlBuilder.replaceExtension(oid, isCritical, encodedValue)

        return this
    }

    /**
     * Remove the extension indicated by OID.
     *
     * @param oid the OID of the extension to be removed.
     * @return this builder object..
     */
    fun removeExtension(oid: ASN1ObjectIdentifier): V2CRLBuilder {
        crlBuilder.removeExtension(oid)

        return this
    }

    /**
     * Generate an X.509 CRL, based on the current issuer and subject
     * using the passed in signatureCalculator.
     *
     * @param signatureCalculator the signature calculator to use to sign the CRL.
     * @return a holder containing the resulting signed certificate.
     */
    fun build(signatureCalculator: SignatureCalculator<AlgorithmIdentifier>): CRL {

        return CRL(crlBuilder.build(KContentSigner(signatureCalculator)))
    }

    /**
     * Generate an X.509 CRL, based on the current issuer and subject
     * using the passed in key and algorithm specification.
     *
     * @param signingKey the key to use to sign the CRL.
     * @param sigAlgSpec the specification for the signature algorithm.
     * @return a holder containing the resulting signed certificate.
     */
    fun build(signingKey: SigningKey, sigAlgSpec: SigAlgSpec): CRL {

        return CRL(crlBuilder.build(KContentSigner(signingKey.signatureCalculator(sigAlgSpec))))
    }
}
