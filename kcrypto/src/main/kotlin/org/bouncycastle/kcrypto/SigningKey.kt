package org.bouncycastle.kcrypto

import KCryptoServices.Companion.helper
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.spec.SigAlgSpec
import org.bouncycastle.kcrypto.spec.asymmetric.DSASigSpec
import org.bouncycastle.kcrypto.spec.asymmetric.ECDSASigSpec
import org.bouncycastle.kcrypto.spec.asymmetric.PKCS1SigSpec
import org.bouncycastle.kcrypto.spec.asymmetric.PSSSigSpec
import java.io.OutputStream
import java.security.PrivateKey
import java.security.Signature

internal class BaseSigner(sigSpec: SigAlgSpec, signingKey: BaseSigningKey) : SignatureCalculator<AlgorithmIdentifier> {

    override val stream: OutputStream
    override val algorithmIdentifier: AlgorithmIdentifier

    val sig: Signature

    init {
        val algName: String
        if (sigSpec is PKCS1SigSpec) {
            algName = simplify(sigSpec.digest.algorithmName + "withRSA")
        } else if (sigSpec is PSSSigSpec) {
            algName = simplify(sigSpec.digest.algorithmName + "withRSAandMGF1")
        } else if (sigSpec is ECDSASigSpec) {
            algName = simplify(sigSpec.digest.algorithmName + "withECDSA")
        } else if (sigSpec is DSASigSpec) {
            algName = simplify(sigSpec.digest.algorithmName + "withDSA")
        } else {
            throw IllegalArgumentException("unknown SigAlgSpec")
        }

        sig = helper.createSignature(algName)

        sig.initSign(signingKey.privKey)

        stream = SigningStream(sig)
              
        algorithmIdentifier = sigSpec.validatedSpec(signingKey).algorithmIdentifier
    }

    private fun simplify(algorithmName: String): String
    {
        return algorithmName.replace("-", "")
    }

    override fun signature(): ByteArray {
        return (stream as SigningStream).signature
    }

    override fun close() {
        stream.close()
    }
}

internal class BaseSigningKey(val privKey: PrivateKey) : SigningKey {

    override val encoding = privKey.encoded

    override fun signatureCalculator(sigAlgSpec: SigAlgSpec): SignatureCalculator<AlgorithmIdentifier> {
        return BaseSigner(sigAlgSpec, this)
    }
}

/**
 * Operational interface for a signing key.
 */
interface SigningKey : org.bouncycastle.kcrypto.PrivateKey {
    /**
     * Return a signature calculator based on this signing key for the passed in algorithm name.
     *
     * @param sigAlgSpec spec for the signature algorithm the calculator is for.
     *
     * @return a SignatureCalculator for the given algorithm
     */
    fun signatureCalculator(sigAlgSpec: SigAlgSpec): SignatureCalculator<AlgorithmIdentifier>
}



