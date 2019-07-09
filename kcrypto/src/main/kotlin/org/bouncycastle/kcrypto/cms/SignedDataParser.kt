package org.bouncycastle.kcrypto.cms

import KCryptoServices
import org.bouncycastle.cert.X509AttributeCertificateHolder
import org.bouncycastle.cert.X509CRLHolder
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cms.CMSSignedDataParser
import org.bouncycastle.cms.CMSTypedStream
import org.bouncycastle.kcrypto.cert.AttributeCertificate
import org.bouncycastle.kcrypto.cert.CRL
import org.bouncycastle.kcrypto.cert.Certificate
import org.bouncycastle.kutil.CollectionStore
import org.bouncycastle.kutil.Store
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import java.io.InputStream

class SignedDataParser {
    private val parser: CMSSignedDataParser

    constructor(inputStream: InputStream) {
        this.parser = CMSSignedDataParser(
            JcaDigestCalculatorProviderBuilder().setProvider(KCryptoServices._provider).build(),
            inputStream
        )
    }

    constructor(input: ByteArray) {
        this.parser = CMSSignedDataParser(
            JcaDigestCalculatorProviderBuilder().setProvider(KCryptoServices._provider).build(),
            input
        )
    }

    constructor(signedData: SignedData, msgStream: TypedContentStream) {
        this.parser = CMSSignedDataParser(
            JcaDigestCalculatorProviderBuilder().setProvider(KCryptoServices._provider).build(),
            CMSTypedStream(msgStream.type, msgStream.stream), signedData.encoding
        )
    }


    val signedContent: TypedContentStream?
        get() = if (parser.signedContent == null) null else TypedContentStream(
            parser.signedContent.contentType,
            parser.signedContent.contentStream
        )

    val signerInfos: Store<SignerInfo> get() = CollectionStore(parser.signerInfos.signers.map { SignerInfo(it) })
    val certificates: Store<Certificate>
        get() = CollectionStore(parser.certificates.getMatches(null).map {
            Certificate(
                (it as X509CertificateHolder).encoded
            )
        })
    val crls: Store<CRL> get() = CollectionStore(parser.crLs.getMatches(null).map { CRL((it as X509CRLHolder).encoded) })
    val attributeCertificates: Store<AttributeCertificate>
        get() = CollectionStore(
            parser.attributeCertificates.getMatches(
                null
            ).map { AttributeCertificate((it as X509AttributeCertificateHolder).encoded) })
    val digestAlgorithms
        get() = parser.digestAlgorithmIDs.toSet()

}