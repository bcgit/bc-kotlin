package org.bouncycastle.kcrypto.internal

import KCryptoServices
import org.bouncycastle.asn1.pkcs.KeyDerivationFunc
import org.bouncycastle.asn1.pkcs.PBKDF2Params
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.jcajce.spec.PBKDF2KeySpec
import org.bouncycastle.kcrypto.PBESymmetricKey
import org.bouncycastle.kcrypto.PBKDF
import org.bouncycastle.kcrypto.SymmetricKey
import org.bouncycastle.kcrypto.spec.KeyGenSpec
import org.bouncycastle.kcrypto.spec.kdf.PBKDF2Spec
import org.bouncycastle.kcrypto.spec.symmetric.AESGenSpec
import org.bouncycastle.kcrypto.spec.symmetric.HMacGenSpec
import javax.crypto.spec.SecretKeySpec

internal class PBKDF2PbKdf(val skdfConf: PBKDF2Spec, val keySpec: KeyGenSpec) : PBKDF {

    override fun symmetricKey(password: CharArray): SymmetricKey {

        val keySize = when (keySpec) {
            is AESGenSpec -> keySpec.keySize
            is HMacGenSpec -> keySpec.keySize
            else -> throw IllegalStateException("unknown KeyGenSpec in PBKDF2")
        }

        val keyAlg = when (keySpec) {
            is AESGenSpec -> "AES"
            is HMacGenSpec -> "HMAC"
            else -> throw IllegalStateException("unknown KeyGenSpec in PBKDF2")
        }

        val params = PBKDF2Params(
                skdfConf.salt,
                skdfConf.iterationCount,
                (keySize + 7) / 8,
                skdfConf.hashAlg)

        val hmacAlg = when (skdfConf.hashAlg.algorithm) {
            PKCSObjectIdentifiers.id_hmacWithSHA1 -> "PBKDF2WITHHMACSHA1"
            PKCSObjectIdentifiers.id_hmacWithSHA224 -> "PBKDF2WITHHMACSHA224"
            PKCSObjectIdentifiers.id_hmacWithSHA256 -> "PBKDF2WITHHMACSHA256"
            PKCSObjectIdentifiers.id_hmacWithSHA384 -> "PBKDF2WITHHMACSHA384"
            PKCSObjectIdentifiers.id_hmacWithSHA512 -> "PBKDF2WITHHMACSHA512"
            else -> throw IllegalStateException("unknown HMAC in PBKDF2")
        }

        val pbkdfKey = PBKDF2KeySpec(password, skdfConf.salt, skdfConf.iterationCount, keySize, skdfConf.hashAlg)
        val fact = KCryptoServices.helper.createSecretKeyFactory(hmacAlg)
        val sKey = fact.generateSecret(pbkdfKey)

        return PBESymmetricKey(keySize, SecretKeySpec(sKey.encoded, keyAlg), PKCSObjectIdentifiers.id_PBES2, KeyDerivationFunc(PKCSObjectIdentifiers.id_PBKDF2, params))
    }
}

