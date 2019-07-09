package org.bouncycastle.kcrypto.cert

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.X509CRLHolder
import org.bouncycastle.kcrypto.Encodable
import org.bouncycastle.kcrypto.KeyType
import org.bouncycastle.kcrypto.VerificationKey
import org.bouncycastle.kcrypto.internal.VerifierProv
import java.math.BigInteger
import java.util.*

class CRL: Encodable
{
    internal val _crl: X509CRLHolder

    constructor(encoding: ByteArray)
    {
       this._crl = X509CRLHolder(encoding)
    }

    internal constructor(holder: X509CRLHolder)
    {
        this._crl = holder
    }

    override val encoding get() = _crl.encoded

    val issuer: X500Name get() = _crl.issuer
    val thisUpdate: Date get() = _crl.thisUpdate
    val nextUpdate get() = _crl.nextUpdate
    val extensions get() = _crl.extensions

    fun findEntryForRevokedCertificate(serialNumber: BigInteger): CRLEntry?
    {
        val entry = _crl.getRevokedCertificate(serialNumber)
        return if (entry != null) CRLEntry(entry) else null
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true

        if (other is CRL) {
            return _crl.equals(other._crl)
        }

        return false
    }

    override fun hashCode(): Int {
        return _crl.hashCode()
    }

    /**
     * Verify the signature on this CRL using the passed in certificate.
     *
     * @param cert the X.509 certificate that contains the public key to verify the signature on this CRL.
     * @return true if the CRL's signature is verified by the certificate's key, false otherwise.
     */
    fun signatureVerifiedBy(cert: Certificate): Boolean
    {
        val holder = cert._cert
        return _crl.isSignatureValid(VerifierProv(
                holder, cert.publicKey(KeyType.VERIFICATION.forAlgorithm(holder.subjectPublicKeyInfo.algorithm))))
    }

    /**
     * Verify the signature on this CRL using the passed in public key.
     *
     * @param pubKey the public key to verify the signature on this CRL.
     * @return true if the CRL's signature is verified by the key, false otherwise.
     */
    fun signatureVerifiedBy(pubKey: VerificationKey): Boolean
    {
        return _crl.isSignatureValid(VerifierProv(null, pubKey))
    }
}