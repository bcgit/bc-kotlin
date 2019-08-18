package org.bouncycastle.kcrypto.internal

import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.kcrypto.ID
import org.bouncycastle.kcrypto.SignatureVerifier
import org.bouncycastle.kcrypto.VerificationKey
import org.bouncycastle.kcrypto.spec.SigAlgSpec
import org.bouncycastle.operator.ContentVerifier
import org.bouncycastle.operator.ContentVerifierProvider
import java.io.OutputStream

internal class VerifierProv(private val cert: X509CertificateHolder?, private val pubKey: VerificationKey, private val id: ID?) : ContentVerifierProvider {

    constructor(cert: X509CertificateHolder?, pubKey: VerificationKey): this(cert, pubKey, null)

    override fun get(algId: AlgorithmIdentifier): ContentVerifier {
        return Verifier(pubKey.signatureVerifier(SigAlgSpec.createSpec(algId, id)))
    }

    override fun hasAssociatedCertificate(): Boolean {
        return cert != null
    }

    override fun getAssociatedCertificate(): X509CertificateHolder? {
        return cert
    }
}

internal class Verifier(private val verifier: SignatureVerifier<AlgorithmIdentifier>) : ContentVerifier {
    override fun getOutputStream(): OutputStream {
        return verifier.stream
    }

    override fun verify(signature: ByteArray): Boolean {
        return verifier.verifies(signature)
    }

    override fun getAlgorithmIdentifier(): AlgorithmIdentifier {
        return verifier.algorithmIdentifier
    }
}