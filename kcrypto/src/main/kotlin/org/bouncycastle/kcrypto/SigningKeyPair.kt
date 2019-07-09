package org.bouncycastle.kcrypto

import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.spec.SigAlgSpec

/**
 * A public/private key pair for signing/verification operations.
 *
 * @property signingKey private key component
 * @property verificationKey public key component
 */
class SigningKeyPair(kp: KeyPair) {
    val signingKey: SigningKey = BaseSigningKey(kp.privateKey)
    val verificationKey: VerificationKey = BaseVerificationKey(kp.publicKey)

    fun signatureCalculator(sigAlgSpec: SigAlgSpec): SignatureCalculator<AlgorithmIdentifier> {
        return signingKey.signatureCalculator(sigAlgSpec)
    }

    fun signatureVerifier(sigAlgSpec: SigAlgSpec): SignatureVerifier<AlgorithmIdentifier> {
        return verificationKey.signatureVerifier(sigAlgSpec)
    }
}