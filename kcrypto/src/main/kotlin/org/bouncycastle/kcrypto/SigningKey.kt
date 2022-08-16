package org.bouncycastle.kcrypto

import KCryptoServices.Companion.helper
import KCryptoServices.Companion.helperFor
import KCryptoServices.Companion.pqcHelper
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.spec.SigAlgSpec
import org.bouncycastle.kcrypto.spec.asymmetric.*
import org.bouncycastle.util.Strings
import java.io.OutputStream
import java.security.PrivateKey
import java.security.Signature

internal class BaseSigner(sigSpec: SigAlgSpec, signingKey: BaseSigningKey) : SignatureCalculator<AlgorithmIdentifier> {

    override val stream: OutputStream
    override val algorithmIdentifier: AlgorithmIdentifier

    val sig: Signature

    init {
        val algName: String = when (sigSpec) {
            is PKCS1SigSpec -> {
                simplify(sigSpec.digest.algorithmName + "withRSA")
            }
            is PSSSigSpec -> {
                simplify(sigSpec.digest.algorithmName + "withRSAandMGF1")
            }
            is ECDSASigSpec -> {
                simplify(sigSpec.digest.algorithmName + "withECDSA")
            }
            is EdDSASigSpec -> {
                sigSpec.algorithmIdentifier.algorithm.id
            }
            is DSASigSpec -> {
                simplify(sigSpec.digest.algorithmName + "withDSA")
            }
            is SM2SigSpec -> {
                simplify(sigSpec.digest.algorithmName + "withSM2")
            }
            is FalconSigSpec -> {
                simplify("Falcon")
            }
            is DilithiumSigSpec -> {
                simplify("Dilithium")
            }
            is SPHINCSPlusSigSpec -> {
                simplify("SPHINCSPlus")
            }
            else ->
                throw IllegalArgumentException("unknown SigAlgSpec")
        }

        sig = helperFor(algName).createSignature(algName)

        if (sigSpec is SM2SigSpec && sigSpec.id != null) {
            sig.setParameter(convert(sigSpec.id))
            sig.initSign(signingKey._privKey)
        }  else {
            sig.initSign(signingKey._privKey)
        }

        stream = SigningStream(sig)
              
        algorithmIdentifier = sigSpec.algorithmIdentifier
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

internal class BaseSigningKey(internal val _privKey: PrivateKey) : SigningKey {

    override val encoding get() = _privKey.encoded

    override fun signatureCalculator(sigAlgSpec: SigAlgSpec): SignatureCalculator<AlgorithmIdentifier> {
        return BaseSigner(sigAlgSpec.validatedSpec(this), this)
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



