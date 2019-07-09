package org.bouncycastle.kcrypto.cms.dsl

import org.bouncycastle.kcrypto.cert.CRL
import org.bouncycastle.kcrypto.cert.Certificate
import org.bouncycastle.kcrypto.cms.CertificateManagementMessage
import org.bouncycastle.kcrypto.cms.CertificateManagementMessageBuilder

fun certificateManagementMessage(block: CertManagementBody.()-> Unit): CertificateManagementMessage = CertManagementBody().apply(block).build()

class CertManagementBody
{
    var certificate: Certificate? = null
    var certificates: List<Certificate>? = null

    var crl: CRL? = null
    var crls: List<CRL>? = null

    fun build(): CertificateManagementMessage
    {
        var builder = CertificateManagementMessageBuilder()

        val cert = certificate
        if (cert != null) {
            builder.addCertificate(cert)
        }
        val certs = certificates
        if (certs != null) {
            for (cert in certs) {
                builder.addCertificate(cert)
            }
        }

        val cRL = crl
        if (cRL != null) {
            builder.addCRL(cRL)
        }
        val cRLs = crls
        if (cRLs != null) {
            for (cRL in cRLs) {
                builder.addCRL(cRL)
            }
        }

        return builder.build()
    }
}


