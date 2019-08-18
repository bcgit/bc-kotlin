package org.bouncycastle.kcrypto.cert

import KCryptoServices
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.kcrypto.*
import org.bouncycastle.kcrypto.internal.VerifierProv

/**
 * Carrier class for an X.509 certificate.
 *
 * @param encoded a DER encoded certificate.
 */
class Certificate(encoding: ByteArray): Encodable
{
    internal val _cert = X509CertificateHolder(encoding)

    val serialNumber get() = _cert.serialNumber

    val issuer get() = _cert.issuer

    val notBefore get() = _cert.notBefore

    val notAfter get() = _cert.notAfter

    val subject get() = _cert.subject

    val subjectPublicKeyInfo get() = _cert.subjectPublicKeyInfo

    val extensions get() = _cert.extensions

    override val encoding: ByteArray = _cert.encoded

    /**
     * Verify the signature on this certificate using the passed in certificate.
     *
     * @param cert the X.509 certificate that contains the public key to verify the signature on this certificate.
     * @return true if the certificate's signature is verified by the certificate's key, false otherwise.
     */
    fun signatureVerifiedBy(cert: Certificate): Boolean
    {
       return signatureVerifiedBy(cert, null)
    }

    /**
     * Verify the signature on this certificate using the passed in certificate.
     *
     * @param cert the X.509 certificate that contains the public key to verify the signature on this certificate.
     * @param id an ID string to associate with the signature generator.
     * @return true if the certificate's signature is verified by the certificate's key, false otherwise.
     */
    fun signatureVerifiedBy(cert: Certificate, id: ID?): Boolean
    {
        val holder = cert._cert
        return _cert.isSignatureValid(VerifierProv(
                holder, cert.publicKey(KeyType.VERIFICATION.forAlgorithm(holder.subjectPublicKeyInfo.algorithm)), id))
    }

    /**
     * Verify the signature on this certificate using the passed in public key.
     *
     * @param pubKey the public key to verify the signature on this certificate.
     * @return true if the certificate's signature is verified by the key, false otherwise.
     */
    fun signatureVerifiedBy(pubKey: VerificationKey): Boolean
    {
        return signatureVerifiedBy(pubKey, null)
    }

    /**
     * Verify the signature on this certificate using the passed in public key.
     *
     * @param pubKey the public key to verify the signature on this certificate.
     * @param id an ID string to associate with the signature generator.
     * @return true if the certificate's signature is verified by the key, false otherwise.
     */
    fun signatureVerifiedBy(pubKey: VerificationKey, id: ID?): Boolean
    {
        return _cert.isSignatureValid(VerifierProv(null, pubKey, id))
    }

    /**
     * Return the public key in this certificate as a signature verification key.
     *
     * @return public key as a VerificationKey
     */
    fun publicKey(keyTemplate: KeyType<VerificationKey>): VerificationKey {
        return KCryptoServices.verificationKey(subjectPublicKeyInfo.encoded, keyTemplate.forAlgorithm(subjectPublicKeyInfo.algorithm))
    }

    /**
     * Return the public key in this certificate as an encryption key.
     *
     * @return public key as an EncryptionKey
     */
    fun publicKey(keyTemplate: KeyType<EncryptionKey>): EncryptionKey {
        return KCryptoServices.encryptionKey(subjectPublicKeyInfo.encoded, keyTemplate.forAlgorithm(subjectPublicKeyInfo.algorithm))
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true

        if (other is Certificate) {
            return _cert.equals(other._cert)
        }

        return false
    }

    override fun hashCode(): Int {
        return _cert.hashCode()
    }
}