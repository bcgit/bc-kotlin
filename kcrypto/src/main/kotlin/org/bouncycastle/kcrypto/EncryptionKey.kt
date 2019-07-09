package org.bouncycastle.kcrypto

import KCryptoServices.Companion.helper
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.spec.AlgSpec
import org.bouncycastle.kcrypto.spec.asymmetric.OAEPSpec
import org.bouncycastle.operator.jcajce.JcaAlgorithmParametersConverter
import java.security.PublicKey
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec

private class BaseEncryptor(algorithm: AlgSpec<AlgorithmIdentifier>, pubKey: PublicKey) : SingleBlockEncryptor<AlgorithmIdentifier> {

    override val algorithmIdentifier: AlgorithmIdentifier

    val cipher: Cipher

    init {
        val digestName = (algorithm as OAEPSpec).digest.algorithmName
        
        cipher = helper.createCipher("RSA/NONE/" + "OAEPwith" + digestName + "andMGF1padding")

        cipher.init(Cipher.ENCRYPT_MODE, pubKey)
                  // TODO:
        algorithmIdentifier = JcaAlgorithmParametersConverter().getAlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP, OAEPParameterSpec.DEFAULT)
    }

    override fun encrypt(data: ByteArray): ByteArray {
        return cipher.doFinal(data)
    }
}

internal class BaseWrapper(algorithm: AlgSpec<AlgorithmIdentifier>, pubKey: PublicKey) : KeyWrapper<AlgorithmIdentifier> {

    override val algorithmIdentifier: AlgorithmIdentifier

    val cipher: Cipher

    init {
        val digestName = (algorithm as OAEPSpec).digest.algorithmName
        
        cipher = helper.createCipher("RSA/NONE/" + "OAEPwith" + digestName + "andMGF1padding")

        cipher.init(Cipher.WRAP_MODE, pubKey)
                  // TODO:
        algorithmIdentifier = JcaAlgorithmParametersConverter().getAlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP, OAEPParameterSpec.DEFAULT)
    }

    override fun wrap(key: SymmetricKey): ByteArray {
        return cipher.wrap((key as BaseSymmetricKey)._key)
    }

    override fun wrap(key: SigningKey): ByteArray {
        return cipher.wrap((key as BaseSigningKey).privKey)
    }
}

internal class BaseEncryptionKey(private var pubKey: PublicKey) : EncryptionKey {

    override val encoding = pubKey.encoded

    override fun singleBlockEncryptor(algSpec: AlgSpec<AlgorithmIdentifier>): SingleBlockEncryptor<AlgorithmIdentifier> {
        return BaseEncryptor(algSpec, pubKey)
    }

    override fun keyWrapper(algSpec: AlgSpec<AlgorithmIdentifier>): KeyWrapper<AlgorithmIdentifier> {
        return BaseWrapper(algSpec, pubKey)
    }
}

/**
 * A public key from an asymmetric key pair.
 */
interface EncryptionKey: WrappingKey, org.bouncycastle.kcrypto.PublicKey {
    fun singleBlockEncryptor(algSpec: AlgSpec<AlgorithmIdentifier>): SingleBlockEncryptor<AlgorithmIdentifier>
}