package org.bouncycastle.kcrypto.cms

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.cms.CMSSignedDataStreamGenerator
import org.bouncycastle.cms.SignerInformationStore
import org.bouncycastle.kcrypto.cert.AttributeCertificate
import org.bouncycastle.kcrypto.cert.CRL
import org.bouncycastle.kcrypto.cert.Certificate
import org.bouncycastle.kutil.Store
import java.io.OutputStream

class SignedDataStreamBuilder {

    private val gen = CMSSignedDataStreamGenerator()

    fun addAttributeCertificate(certificate: AttributeCertificate): SignedDataStreamBuilder {
        gen.addAttributeCertificate(certificate._cert)
        return this
    }

    fun addAttributeCertificates(certificates: Store<AttributeCertificate>): SignedDataStreamBuilder {
        for (cert in certificates.iterator()) {
            gen.addAttributeCertificate(cert._cert)
        }
        return this
    }

    fun addCertificate(certificate: Certificate): SignedDataStreamBuilder {
        gen.addCertificate(certificate._cert)
        return this
    }

    fun addCertificates(certificates: Store<Certificate>): SignedDataStreamBuilder {
        for (cert in certificates.iterator()) {
            gen.addCertificate(cert._cert)
        }
        return this
    }

    fun addCRL(crl: CRL): SignedDataStreamBuilder {
        gen.addCRL(crl._crl)
        return this
    }

    fun addCRLs(crls: Store<CRL>): SignedDataStreamBuilder {
        for (crl in crls.iterator()) {
            gen.addCRL(crl._crl)
        }
        return this
    }

    fun addSigners(signerInfo: Store<SignerInfo>): SignedDataStreamBuilder {
        gen.addSigners(SignerInformationStore(signerInfo.map { it.signerInf }))
        return this
    }

    fun addSignerInfoGenerator(signerInfoGenerator: SignerInfoGenerator) {
        gen.addSignerInfoGenerator(signerInfoGenerator.generate())
    }

    fun build(targetStream: OutputStream): OutputStream {
        return gen.open(targetStream)
    }

    fun build(targetStream: OutputStream, encapsulate: Boolean): OutputStream {
        return gen.open(targetStream, encapsulate)
    }

    fun build(targetStream: OutputStream, encapsulate: Boolean, dataOutputStream: OutputStream): OutputStream {
        return gen.open(targetStream, encapsulate, dataOutputStream)
    }

    fun build(eContentType: ASN1ObjectIdentifier, out: OutputStream, encapsulate: Boolean): OutputStream {
        return gen.open(eContentType, out, encapsulate, null)
    }

    fun build(
        eContentType: ASN1ObjectIdentifier,
        out: OutputStream,
        encapsulate: Boolean,
        dataOutputStream: OutputStream
    ): OutputStream {
        return gen.open(eContentType, out, encapsulate, dataOutputStream)
    }
}