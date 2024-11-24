package org.bouncycastle.kcrypto.dsl

import KCryptoServices
import org.bouncycastle.kcrypto.EncryptingKeyPair
import org.bouncycastle.kcrypto.SigningKeyPair
import org.bouncycastle.kcrypto.param.DSADomainParameters
import org.bouncycastle.kcrypto.spec.EncPairGenSpec
import org.bouncycastle.kcrypto.spec.SignPairGenSpec
import org.bouncycastle.kcrypto.spec.asymmetric.*
import java.math.BigInteger
import java.security.Provider
import java.security.Security
import java.security.spec.RSAKeyGenParameterSpec

/**
 * KeyBuilder DSL to assist in the creation of keys
 */
class SigningKeyBuilder {
    private lateinit var spec: SignPairGenSpec

    fun setSpec(genSpec: SignPairGenSpec) {
        this.spec = genSpec
    }

    fun signingKeyPair(): SigningKeyPair {
        return KCryptoServices.signingKeyPair(spec)
    }
}

/**
 * Specify the provider
 * @param provider = provider instance
 */
fun using(provider: Provider) = KCryptoServices.setProvider(provider)

/**
 * Specify the provider by name.
 * @param provider = provider name
 */
fun using(provider: String) = KCryptoServices.setProvider(Security.getProvider(provider))

/**
 * Create a signing key pair
 * @param block initialisation
 */
fun signingKeyPair(block: SigningKeyBuilder.() -> Unit): SigningKeyPair = SigningKeyBuilder().apply(block).signingKeyPair()

/**
 * Initialize a RSA key pair.
 * @param block initialization block
 */
fun SigningKeyBuilder.rsa(block: RsaParams.() -> Unit) {
    val p = RsaParams().apply(block)

    setSpec(RSAGenSpec(p.keySize, KCryptoServices.secureRandom))
}

/**
 * Initialize an EC Key pair
 * @param block initialization block.
 */
fun SigningKeyBuilder.ec(block: EcParams.() -> Unit) {
    val p = EcParams().apply(block)

    setSpec(ECGenSpec(p.curveName, KCryptoServices.secureRandom))
}

/**
 * Initialize an DSA Key pair
 * @param block initialization block.
 */
fun SigningKeyBuilder.dsa(block: DsaParams.() -> Unit) {
    val p = DsaParams().apply(block)

    setSpec(DSAGenSpec(p.domainParameters, KCryptoServices.secureRandom))
}

/**
 * Initialize an EdDSA Key pair
 * @param block initialization block.
 */
fun SigningKeyBuilder.edDsa(block: EdDsaParams.() -> Unit) {
    val p = EdDsaParams().apply(block)

    setSpec(EdDSAGenSpec(p.curveName, KCryptoServices.secureRandom))
}

/**
 * Initialize an Falcon Key pair
 * @param block initialization block.
 */
fun SigningKeyBuilder.falcon(block: FalconParams.() -> Unit) {
    val p = FalconParams().apply(block)

    setSpec(FalconGenSpec(p.parameterSet, KCryptoServices.secureRandom))
}

/**
 * Initialize an Falcon Key pair
 * @param block initialization block.
 */
fun SigningKeyBuilder.mlDsa(block: MLDSAParams.() -> Unit) {
    val p = MLDSAParams().apply(block)

    setSpec(MLDSAGenSpec(p.parameterSet, KCryptoServices.secureRandom))
}

/**
 * Initialize an sphincs+ Key pair
 * @param block initialization block.
 */
fun SigningKeyBuilder.slhDsa(block: SLHDSAParams.() -> Unit) {
    val p = SLHDSAParams().apply(block)

    setSpec(SLHDSAGenSpec(p.parameterSet, KCryptoServices.secureRandom))
}

/**
 * Initialize an sphincs+ Key pair
 * @param block initialization block.
 */
fun SigningKeyBuilder.lms(block: LMSParams.() -> Unit) {
    val p = LMSParams().apply(block)

    setSpec(LMSGenSpec(p.sigParameterSet, p.otsParameterSet, KCryptoServices.secureRandom))
}

class EncryptingKeyBuilder {
    private lateinit var spec: EncPairGenSpec

    fun setSpec(genSpec: EncPairGenSpec) {
        this.spec = genSpec
    }

    fun encryptingKeyPair(): EncryptingKeyPair {
        return KCryptoServices.encryptingKeyPair(spec)
    }
}

/**
 * Create a signing key pair
 * @param block initialisation
 */
fun encryptingKeyPair(block: EncryptingKeyBuilder.() -> Unit): EncryptingKeyPair = EncryptingKeyBuilder().apply(block).encryptingKeyPair()

/**
 * Initialize a RSA key pair.
 * @param block initialization block
 */
fun EncryptingKeyBuilder.rsa(block: RsaParams.() -> Unit) {
    val p = RsaParams().apply(block)

    setSpec(RSAGenSpec(p.keySize, KCryptoServices.secureRandom))
}

/**
 * Initialize a MLKEM key pair.
 * @param block initialization block
 */
fun EncryptingKeyBuilder.kyber(block: MLKEMParams.() -> Unit) {
    val p = MLKEMParams().apply(block)

    setSpec(MLKEMGenSpec(p.paramSet, KCryptoServices.secureRandom))
}

/**
 * Initialize a NTRU key pair.
 * @param block initialization block
 */
fun EncryptingKeyBuilder.ntru(block: NtruParams.() -> Unit) {
    val p = NtruParams().apply(block)

    setSpec(NTRUGenSpec(p.parameterSet, KCryptoServices.secureRandom))
}

/**
 * RSA Parameters
 */
data class RsaParams(
    var keySize: Int = 2048,
    var certainty: Int = 120,
    var publicExponent: BigInteger = RSAKeyGenParameterSpec.F4
) {
}

/**
 * MLKEM Parameters
 */
data class MLKEMParams(var paramSet: String = "kyber512")

/**
 * NTRU Parameters
 */
data class NtruParams(var parameterSet: String = "ntruhrss701")

/**
 * EC Parameters
 */
data class EcParams(var curveName: String = "P-256")

/**
 * DSA Parameters
 */
data class DsaParams(var domainParameters: DSADomainParameters = DSADomainParameters.DEF_2048)

/**
 * EdDSA Parameters
 */
data class EdDsaParams(var curveName: String = "ED25519")

/**
 * Falcon Parameters
 */
data class FalconParams(var parameterSet: String = "falcon-512")

/**
 * MLDSA Parameters
 */
data class MLDSAParams(var parameterSet: String = "ML-DSA-87")

/**
 * SphincsPlus Parameters
 */
data class SLHDSAParams(var parameterSet: String = "shake_128f")

/**
 * LMS Parameters
 */
data class LMSParams(var sigParameterSet: String = "lms-sha256-n32-h10", var otsParameterSet: String = "sha256-n32-w2")