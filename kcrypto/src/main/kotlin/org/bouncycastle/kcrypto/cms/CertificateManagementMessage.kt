package org.bouncycastle.kcrypto.cms

import org.bouncycastle.cert.X509AttributeCertificateHolder
import org.bouncycastle.cert.X509CRLHolder
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.kcrypto.Encodable
import org.bouncycastle.kcrypto.cert.AttributeCertificate
import org.bouncycastle.kcrypto.cert.CRL
import org.bouncycastle.kcrypto.cert.Certificate
import org.bouncycastle.kutil.CollectionStore
import org.bouncycastle.kutil.Store

class CertificateManagementMessage(encoding: ByteArray): Encodable {

    private val dataMessage: CMSSignedData

    init {
        dataMessage = CMSSignedData(encoding)
        if (!dataMessage.isCertificateManagementMessage)
        {
            throw IllegalArgumentException("encoding does not represent a certificate managent message")
        }
    }

    override val encoding: ByteArray get() = dataMessage.encoded

    val certificates: Store<Certificate> get() = CollectionStore(dataMessage.certificates.getMatches(null).map { Certificate((it as X509CertificateHolder).encoded) })
    val crls: Store<CRL> get() = CollectionStore(dataMessage.crLs.getMatches(null).map { CRL((it as X509CRLHolder).encoded) })
    val attributeCertificates: Store<AttributeCertificate> get() = CollectionStore(dataMessage.attributeCertificates.getMatches(null).map { AttributeCertificate((it as X509AttributeCertificateHolder).encoded) })
}