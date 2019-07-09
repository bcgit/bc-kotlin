package org.bouncycastle.kcrypto.internal

import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.DigestCalculator

import java.io.OutputStream

internal class KDigestCalculator(private val digCalc: DigestCalculator<AlgorithmIdentifier>): org.bouncycastle.operator.DigestCalculator
{
    override fun getOutputStream(): OutputStream {
        return digCalc.stream
    }

    override fun getDigest(): ByteArray {
        return digCalc.digest()
    }

    override fun getAlgorithmIdentifier(): AlgorithmIdentifier {
        return digCalc.algorithmIdentifier
    }

}