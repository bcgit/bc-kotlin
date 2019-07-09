package org.bouncycastle.kcrypto.cert

import org.bouncycastle.cert.X509AttributeCertificateHolder
import org.bouncycastle.kcrypto.Encodable

class AttributeCertificate(encoding: ByteArray): Encodable
{
    internal val _cert = X509AttributeCertificateHolder(encoding)

    override val encoding: ByteArray = _cert.encoded

    override fun equals(other: Any?): Boolean {
        if (this === other) return true

        if (other is AttributeCertificate) {
            return _cert.equals(other._cert)
        }

        return false
    }

    override fun hashCode(): Int {
        return _cert.hashCode()
    }
}