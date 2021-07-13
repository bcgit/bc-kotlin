package org.bouncycastle.kcrypto.dsl

import KCryptoServices
import org.bouncycastle.kcrypto.EncryptingKeyPair
import org.bouncycastle.kcrypto.SigningKeyPair
import org.bouncycastle.kcrypto.param.DSADomainParameters
import org.bouncycastle.kcrypto.spec.EncPairGenSpec
import org.bouncycastle.kcrypto.spec.SignPairGenSpec
import org.bouncycastle.kcrypto.spec.asymmetric.DSAGenSpec
import org.bouncycastle.kcrypto.spec.asymmetric.ECGenSpec
import org.bouncycastle.kcrypto.spec.asymmetric.EdDSAGenSpec
import org.bouncycastle.kcrypto.spec.asymmetric.RSAGenSpec
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
 * RSA Parameters
 */
data class RsaParams(
    var keySize: Int = 2048,
    var certainty: Int = 120,
    var publicExponent: BigInteger = RSAKeyGenParameterSpec.F4
) {
}

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