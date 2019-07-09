package org.bouncycastle.kcrypto.pkcs

import KCryptoServices
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo
import org.bouncycastle.asn1.pkcs.PBES2Parameters
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.*
import org.bouncycastle.kcrypto.internal.DecryptorProviderImpl
import org.bouncycastle.kcrypto.internal.findSymKeyGenSpec
import org.bouncycastle.kcrypto.spec.kdf.PBKDF2Spec
import org.bouncycastle.kcrypto.spec.kdf.ScryptSpec
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo

/**
 * A PKCS8 Encrypted Private Key
 */
class PKCS8EncryptedPrivateKey(private val info: EncryptedPrivateKeyInfo) : Encodable {

    constructor(privateKeyInfo: ByteArray) : this(EncryptedPrivateKeyInfo.getInstance(privateKeyInfo))

    override val encoding: ByteArray
        get() = info.encoded

    private fun extractKey(decryptionKey: SymmetricKey): PrivateKeyInfo
    {
        var inputDecryptorProvider :org.bouncycastle.operator.InputDecryptorProvider = DecryptorProviderImpl(decryptionKey)

        var wrapper = PKCS8EncryptedPrivateKeyInfo(info)
        
        return wrapper.decryptPrivateKeyInfo(inputDecryptorProvider)
    }

    val encryptionAlgorithm: AlgorithmIdentifier get() = info.encryptionAlgorithm

    val isPBEBased get() = encryptionAlgorithm.algorithm.equals(PKCSObjectIdentifiers.id_PBES2)

    val pbkdf: PBKDF? = if (isPBEBased) {
        var pbeS2 = PBES2Parameters.getInstance(encryptionAlgorithm.parameters)
        when (pbeS2.keyDerivationFunc.algorithm) {
            MiscObjectIdentifiers.id_scrypt -> KCryptoServices.pbkdf(ScryptSpec(AlgorithmIdentifier.getInstance(pbeS2.keyDerivationFunc)),
                    findSymKeyGenSpec(AlgorithmIdentifier.getInstance(pbeS2.encryptionScheme)))
            PKCSObjectIdentifiers.id_PBKDF2 -> KCryptoServices.pbkdf(PBKDF2Spec(AlgorithmIdentifier.getInstance(pbeS2.keyDerivationFunc)),
                    findSymKeyGenSpec(AlgorithmIdentifier.getInstance(pbeS2.encryptionScheme)))
            else -> throw IllegalStateException("unknown PBE algorithm: " + pbeS2.keyDerivationFunc.algorithm)
        }
    } else {
        null
    }

    fun privateKey(decryptionKey: SymmetricKey, keyTemplate: KeyType<SigningKey>): SigningKey {
        return KCryptoServices.signingKey(extractKey(decryptionKey).encoded, keyTemplate)
    }

    fun privateKey(decryptionKey: SymmetricKey, keyTemplate: KeyType<DecryptionKey>): DecryptionKey {
        return KCryptoServices.decryptionKey(extractKey(decryptionKey).encoded, keyTemplate)
    }


}