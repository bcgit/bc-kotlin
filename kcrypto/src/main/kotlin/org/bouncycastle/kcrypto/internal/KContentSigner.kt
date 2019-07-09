package org.bouncycastle.kcrypto.internal

import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.SignatureCalculator
import org.bouncycastle.operator.ContentSigner
import java.io.OutputStream

internal class KContentSigner(var s: SignatureCalculator<AlgorithmIdentifier>) : ContentSigner {

    override fun getAlgorithmIdentifier(): AlgorithmIdentifier {
        return s.algorithmIdentifier
    }

    override fun getOutputStream(): OutputStream {
        return s.stream
    }

    override fun getSignature(): ByteArray {
        return s.signature()
    }

}