package org.bouncycastle.kcrypto.cms

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.CMSTypedData
import org.bouncycastle.cms.SignerInformationStore
import org.bouncycastle.kcrypto.cert.AttributeCertificate
import org.bouncycastle.kcrypto.cert.CRL
import org.bouncycastle.kcrypto.cert.Certificate
import org.bouncycastle.kutil.Store
import java.io.OutputStream

class SignedDataBuilder {

    private val gen = CMSSignedDataGenerator()

    fun addAttributeCertificate(certificate: AttributeCertificate): SignedDataBuilder
    {
        gen.addAttributeCertificate(certificate._cert)
        return this
    }

    fun addAttributeCertificates(certificates: Store<AttributeCertificate>): SignedDataBuilder
    {
        for (cert in certificates.iterator()) {
            gen.addAttributeCertificate(cert._cert)
        }
        return this
    }

    fun addCertificate(certificate: Certificate): SignedDataBuilder
    {
        gen.addCertificate(certificate._cert)
        return this
    }

    fun addSigners(signerInfo: Store<SignerInfo>): SignedDataBuilder {
        gen.addSigners(SignerInformationStore(signerInfo.map { it.signerInf }))
        return this
    }


    fun addCertificates(certificates: Store<Certificate>): SignedDataBuilder
    {
        for (cert in certificates.iterator()) {
            gen.addCertificate(cert._cert)
        }
        return this
    }

    fun addCRL(crl: CRL): SignedDataBuilder
    {
        gen.addCRL(crl._crl)
        return this
    }

    fun addCRLs(crls: Store<CRL>): SignedDataBuilder
    {
        for (crl in crls.iterator()) {
            gen.addCRL(crl._crl)
        }
        return this
    }

    fun addSignerInfoGenerator(signerInfoGenerator: SignerInfoGenerator)
    {
        gen.addSignerInfoGenerator(signerInfoGenerator.generate())
    }

    fun build(content: TypedContent): SignedData
    {
        return SignedData(gen.generate(KTypedData(content)).encoded)
    }

    fun build(content: TypedContent, encapsulate: Boolean): SignedData
    {
        return SignedData(gen.generate(KTypedData(content), encapsulate).encoded)
    }
}

private class KTypedData(private val data: TypedContent): CMSTypedData
{
    override fun getContent(): Any {
        return data.content as Any
    }

    override fun write(sOut: OutputStream?) {
        if (sOut != null) {
            sOut.write(data.content)
        }
    }

    override fun getContentType(): ASN1ObjectIdentifier {
        return data.type
    }
}