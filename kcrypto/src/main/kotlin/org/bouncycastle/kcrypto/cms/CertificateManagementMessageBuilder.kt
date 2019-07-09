package org.bouncycastle.kcrypto.cms

import org.bouncycastle.cms.CMSAbsentContent
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.kcrypto.cert.AttributeCertificate
import org.bouncycastle.kcrypto.cert.CRL
import org.bouncycastle.kcrypto.cert.Certificate
import org.bouncycastle.kutil.Store

class CertificateManagementMessageBuilder
{
    private val gen = CMSSignedDataGenerator()

    fun addAttributeCertificate(certificate: AttributeCertificate): CertificateManagementMessageBuilder
    {
        gen.addAttributeCertificate(certificate._cert)
        return this
    }

    fun addAttributeCertificates(vararg certificates: AttributeCertificate): CertificateManagementMessageBuilder
    {
        for (cert in certificates.iterator()) {
            gen.addAttributeCertificate(cert._cert)
        }
        return this
    }

    fun addAttributeCertificates(certificates: Store<AttributeCertificate>): CertificateManagementMessageBuilder
    {
        for (cert in certificates.iterator()) {
            gen.addAttributeCertificate(cert._cert)
        }
        return this
    }

    fun addCertificate(certificate: Certificate): CertificateManagementMessageBuilder
    {
        gen.addCertificate(certificate._cert)
        return this
    }

    fun addCertificates(vararg certificates: Certificate): CertificateManagementMessageBuilder
    {
        for (cert in certificates.iterator()) {
            gen.addCertificate(cert._cert)
        }
        return this
    }

    fun addCertificates(certificates: Store<Certificate>): CertificateManagementMessageBuilder
    {
        for (cert in certificates.iterator()) {
            gen.addCertificate(cert._cert)
        }
        return this
    }

    fun addCRL(crl: CRL): CertificateManagementMessageBuilder
    {
        gen.addCRL(crl._crl)
        return this
    }

    fun addCRLs(vararg crls: CRL): CertificateManagementMessageBuilder
    {
        for (crl in crls.iterator()) {
            gen.addCRL(crl._crl)
        }
        return this
    }

    fun addCRLs(crls: Store<CRL>): CertificateManagementMessageBuilder
    {
        for (crl in crls.iterator()) {
            gen.addCRL(crl._crl)
        }
        return this
    }

    fun build(): CertificateManagementMessage
    {
        return CertificateManagementMessage(gen.generate(CMSAbsentContent(), true).encoded)
    }
}