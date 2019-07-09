package org.bouncycastle.kcrypto.pkcs

import KCryptoServices
import org.bouncycastle.kcrypto.Encodable
import org.bouncycastle.kcrypto.EncryptionKey
import org.bouncycastle.kcrypto.KeyType
import org.bouncycastle.kcrypto.VerificationKey
import org.bouncycastle.kcrypto.cert.Certificate
import org.bouncycastle.kcrypto.internal.VerifierProv
import org.bouncycastle.pkcs.PKCS10CertificationRequest

/**
 * Carrier class for a PKCS#10 certification request.
 *
 * @param encoded a DER encoded PKCS#10 request.
 */
class PKCS10Request(private val encoded: ByteArray) : Encodable
{
    internal var _request: PKCS10CertificationRequest

    init {
        _request = PKCS10CertificationRequest(encoded)
    }

    override val encoding: ByteArray
        get() = encoded

    val subjectPublicKeyInfo = _request.subjectPublicKeyInfo

    fun publicKey(keyTemplate: KeyType<VerificationKey>): VerificationKey {
        return KCryptoServices.verificationKey(subjectPublicKeyInfo.encoded, keyTemplate)
    }

    fun publicKey(keyTemplate: KeyType<EncryptionKey>): EncryptionKey {
        return KCryptoServices.encryptionKey(subjectPublicKeyInfo.encoded, keyTemplate)
    }

    /**
     * Verify the signature on this PKCS#10 request using the public key contained in the request.
     *
     * @return true if the request's signature is verified by the its own key, false otherwise.
     */
    fun signatureVerifies(): Boolean
    {
        return _request.isSignatureValid(VerifierProv(null,
                this.publicKey(KeyType.VERIFICATION.forAlgorithm(subjectPublicKeyInfo.algorithm))))
    }

    /**
     * Verify the signature on this PKCS#10 request using the passed in certificate.
     *
     * @param cert the X.509 certificate that contains the public key to verify the signature on this request.
     * @return true if the request's signature is verified by the certificate's key, false otherwise.
     */
    fun signatureVerifiedBy(cert: Certificate): Boolean
    {
        return _request.isSignatureValid(VerifierProv(
                cert._cert, cert.publicKey(KeyType.VERIFICATION.forAlgorithm(subjectPublicKeyInfo.algorithm))))
    }

    /**
     * Verify the signature on this PKCS#10 request using the passed in public key.
     *
     * @param pubKey the public key to verify the signature on this request.
     * @return true if the request's signature is verified by the key, false otherwise.
     */
    fun signatureVerifiedBy(pubKey: VerificationKey): Boolean
    {
        return _request.isSignatureValid(VerifierProv(null, pubKey))
    }
}