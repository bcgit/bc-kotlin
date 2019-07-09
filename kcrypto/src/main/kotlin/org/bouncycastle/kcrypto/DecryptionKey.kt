package org.bouncycastle.kcrypto

import KCryptoServices
import KCryptoServices.Companion.helper
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.spec.AlgSpec
import org.bouncycastle.kcrypto.spec.asymmetric.OAEPSpec
import org.bouncycastle.operator.jcajce.JcaAlgorithmParametersConverter
import java.security.PrivateKey
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.OAEPParameterSpec

internal class BaseDecryptor(algorithm: AlgSpec<AlgorithmIdentifier>, privKey: PrivateKey) : SingleBlockDecryptor<AlgorithmIdentifier> {

    override val algorithmIdentifier: AlgorithmIdentifier

    val cipher: Cipher

    init {
        val digestName = (algorithm as OAEPSpec).digest.algorithmName

        cipher = helper.createCipher("RSA/NONE/" + "OAEPwith" + digestName + "andMGF1padding")

        cipher.init(Cipher.DECRYPT_MODE, privKey)
                  // TODO:
        algorithmIdentifier = JcaAlgorithmParametersConverter().getAlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP, OAEPParameterSpec.DEFAULT)
    }

    override fun decrypt(data: ByteArray): ByteArray {
        return cipher.doFinal(data)
    }
}

internal class BaseKeyUnwrapper(algorithm: AlgSpec<AlgorithmIdentifier>, private val privKey: PrivateKey) : KeyUnwrapper<AlgorithmIdentifier> {

    override val algorithmIdentifier: AlgorithmIdentifier

    val cipher: Cipher

    init {
        val digestName = (algorithm as OAEPSpec).digest.algorithmName

        cipher = helper.createCipher("RSA/NONE/" + "OAEPwith" + digestName + "andMGF1padding")


                  // TODO:
        algorithmIdentifier = JcaAlgorithmParametersConverter().getAlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP, OAEPParameterSpec.DEFAULT)
    }
    
    override fun unwrap(wrappedKey: ByteArray, keyTemplate: KeyType<SymmetricKey>): SymmetricKey {

        cipher.init(Cipher.UNWRAP_MODE, privKey)
        val secretKey = cipher.unwrap(wrappedKey, keyTemplate.algorithm, Cipher.SECRET_KEY) as SecretKey
        return BaseSymmetricKey(secretKey.encoded.size * 8, secretKey)
    }

    override fun unwrap(wrappedKey: ByteArray, keyTemplate: KeyType<SigningKey>): SigningKey {

        if (keyTemplate.algorithm.equals("Signing")) {
            cipher.init(Cipher.DECRYPT_MODE, privKey)
            
            return KCryptoServices.signingKey(cipher.doFinal(wrappedKey), keyTemplate)
        }
        cipher.init(Cipher.UNWRAP_MODE, privKey)

        return BaseSigningKey(cipher.unwrap(wrappedKey, keyTemplate.algorithm, Cipher.PRIVATE_KEY) as PrivateKey)
    }

    override fun unwrap(wrappedKey: ByteArray, keyTemplate: KeyType<DecryptionKey>): DecryptionKey {

        if (keyTemplate.algorithm.equals("Decryption")) {
            cipher.init(Cipher.DECRYPT_MODE, privKey)

            return KCryptoServices.decryptionKey(cipher.doFinal(wrappedKey), keyTemplate)
        }
        cipher.init(Cipher.UNWRAP_MODE, privKey)

        return BaseDecryptionKey(cipher.unwrap(wrappedKey, keyTemplate.algorithm, Cipher.PRIVATE_KEY) as PrivateKey)
    }
}

internal class BaseDecryptionKey(private var privKey: PrivateKey) : DecryptionKey {

    override val encoding = privKey.encoded

    override fun singleBlockDecryptor(algSpec: AlgSpec<AlgorithmIdentifier>): SingleBlockDecryptor<AlgorithmIdentifier> {
        return BaseDecryptor(algSpec, privKey)
    }

    override fun keyUnwrapper(algSpec: AlgSpec<AlgorithmIdentifier>): KeyUnwrapper<AlgorithmIdentifier> {
        return BaseKeyUnwrapper(algSpec, privKey)
    }
}

/**
 * A decryption key is the private half of a key pair. Decryption keys can be used for unwrapping as well.
 */
interface DecryptionKey: UnwrappingKey, Encodable {
    /**
     * Create a decryptor for processing a single block.
     *
     * @param algSpec the algorithm specification the decryptor should meet.
     * @return an appropriate decryptor for handling a block of encrypted data.
     */
    fun singleBlockDecryptor(algSpec: AlgSpec<AlgorithmIdentifier>): SingleBlockDecryptor<AlgorithmIdentifier>
}



