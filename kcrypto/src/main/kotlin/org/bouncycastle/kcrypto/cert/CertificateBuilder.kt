package org.bouncycastle.kcrypto.cert

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.Extensions
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509v1CertificateBuilder
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.kcrypto.PublicKey
import org.bouncycastle.kcrypto.SignatureCalculator
import org.bouncycastle.kcrypto.SigningKey
import org.bouncycastle.kcrypto.spec.SigAlgSpec
import org.bouncycastle.operator.ContentSigner
import java.io.OutputStream
import java.math.BigInteger
import java.util.*

private class Signer(var s: SignatureCalculator<AlgorithmIdentifier>) : ContentSigner {

    override fun getAlgorithmIdentifier(): AlgorithmIdentifier {
        return s.algorithmIdentifier
    }

    override fun getOutputStream(): OutputStream {
        return s.stream
    }

    override fun getSignature(): ByteArray {
        return s.signature()
    }

}

/**
 * Builder class for X.509 Certificates.
 * <p>
 * By default this will produce a version 1 certificate if the setExtensions() method is not called.
 *
 * @param signatureCalculator the signature calculator based on the issuer's private key.
 * @param issuerName the X.500 name for the certificate issuer.
 */
class CertificateBuilder(private val signatureCalculator: SignatureCalculator<AlgorithmIdentifier>, private val issuerName: X500Name) {

    /**
     * Create an X.509 certificate builder based on this signing key for the passed in signature specification.
     *
     * @param signingKey the key to use to sign the final certificate.
     * @param sigAlgSpec name of the signature algorithm the calculator is for.
     * @param issuerName the X.500 Name to use as the certificate issuer name.
     */
    constructor(signingKey: SigningKey, sigAlgSpec: SigAlgSpec, issuerName: X500Name): this(signingKey.signatureCalculator(sigAlgSpec), issuerName)

    /**
     * Create an X.509 certificate builder based on this signing key for the passed in signature specification.
     *
     * @param signingKey the key to use to sign the final certificate.
     * @param sigAlgSpec name of the signature algorithm the calculator is for.
     * @param issuerCert the Certificate to use as the source of the certificate issuer name.
     */
    constructor(signingKey: SigningKey, sigAlgSpec: SigAlgSpec, issuerCert: Certificate): this(signingKey.signatureCalculator(sigAlgSpec), issuerCert._cert.subject)

    private var notAfter: Date = Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000) // one year
    private var notBefore: Date = Date(System.currentTimeMillis() - 1000)

    private var extSet : Boolean = false;
    private var extensions : Extensions? = null;

    /**
     * Set the time from which the certificate is valid for use.
     *
     * @param startDate date at which the certificate becomes valid.
     * @return this builder object.
     */
    fun setNotBefore(startDate: Date): CertificateBuilder {
        this.notBefore = Date(startDate.time)
        return this
    }

    /**
     * Set the time at which the certificate can no longer be used.
     *
     * @param expiryDate date at which the certificate becomes invalid.
     * @return this builder object.
     */
    fun setNotAfter(expiryDate: Date): CertificateBuilder {
        this.notAfter = Date(expiryDate.time)
        return this
    }

    /**
     * Provide the certificate extensions for the builder to use.
     *
     * @param extensions the extension set to use for the certificate.
     * @return this builder object.
     */
    fun setExtensions(extensions: Extensions?): CertificateBuilder
    {
        this.extSet = true;
        this.extensions = extensions;
        return this
    }

    /**
     * Build a self-issued certificate.
     *
     * @param serialNumber the serial number for the certificate.
     * @param publicKey the public key to issue the certificate for (usually the one corresponding to the issuer private key).
     */
    fun build(serialNumber: BigInteger, publicKey: PublicKey): Certificate {
        return build(serialNumber, issuerName, publicKey)
    }

    /**
     * Build a certificate for the passed in subject and associated public key.
     *
     * @param serialNumber the serial number for the certificate.
     * @param subjectName the X.500 name to be associated with the public key.
     * @param publicKey the public key to issue the certificate for.
     */
    fun build(serialNumber: BigInteger, subjectName: X500Name, publicKey: PublicKey): Certificate {
        return build(serialNumber, subjectName, SubjectPublicKeyInfo.getInstance(publicKey.encoding))
    }

    /**
     * Build a self-issued certificate based on a SubjectPublicKeyInfo.
     *
     * @param serialNumber the serial number for the certificate.
     * @param publicKeyInfo the public key to issue the certificate for (usually the one corresponding to the issuer private key).
     */
    fun build(serialNumber: BigInteger, publicKeyInfo: SubjectPublicKeyInfo): Certificate {
        return build(serialNumber, issuerName, publicKeyInfo)
    }

    /**
     * Build a certificate for the passed in subject and associated SubjectPublicKeyInfo.
     *
     * @param serialNumber the serial number for the certificate.
     * @param subjectName the X.500 name to be associated with the public key.
     * @param publicKeyInfo the public key to issue the certificate for.
     */
    fun build(serialNumber: BigInteger, subjectName: X500Name, publicKeyInfo: SubjectPublicKeyInfo): Certificate {

        val exts = extensions

        if (extSet) {
            var bldr = X509v3CertificateBuilder(
                    issuerName, serialNumber, notBefore, notAfter, subjectName, publicKeyInfo)

            if (exts != null) {
                for (oid in exts.oids()) {
                    bldr.addExtension(exts.getExtension(oid as ASN1ObjectIdentifier?))
                }
            }

            return Certificate(bldr.build(Signer(signatureCalculator)).encoded)
        }
        else {
            var bldr = X509v1CertificateBuilder(
                    issuerName, serialNumber, notBefore, notAfter, subjectName, publicKeyInfo)

            return Certificate(bldr.build(Signer(signatureCalculator)).encoded)
        }
    }
}