package org.bouncycastle.kcrypto.dsl

import KCryptoServices
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.Encryptor
import org.bouncycastle.kcrypto.KeyType
import org.bouncycastle.kcrypto.PBKDF
import org.bouncycastle.kcrypto.SymmetricKey
import org.bouncycastle.kcrypto.pkcs.dsl.EncryptedPrivateKeyBody
import org.bouncycastle.kcrypto.spec.SymAlgSpec
import org.bouncycastle.kcrypto.spec.kdf.PBKDF2Spec
import org.bouncycastle.kcrypto.spec.kdf.ScryptSpec
import org.bouncycastle.kcrypto.spec.symmetric.*
import org.bouncycastle.util.encoders.Hex

/**
 *
 */
class EncryptionDetails(private val parent: EncryptedPrivateKeyBody, private val template: KeyType<SymmetricKey>, private var algSpec: SymAlgSpec<AlgorithmIdentifier>) {

    private var pbe: PBKDF? = null

    /**
     * Tag size.
     */
    infix fun tagSize(tagSize: Int): EncryptionDetails {

        var currentSpec = algSpec
        when (currentSpec) {
            is GCMSpec -> algSpec = GCMSpec(currentSpec.iv, tagSize)
            is CCMSpec -> algSpec = CCMSpec(currentSpec.iv, tagSize)
            else -> throw IllegalStateException("unknown spec encountered")
        }

        return this
    }

    /**
     * using 'spec', eg ScryptSpec or a "key" instance.
     * using SScryptDetails(..)
     * using key("AES")
     */
    infix fun using(detail: Any): EncryptionDetails {

        when (detail) {
            is key -> {
                val k = KCryptoServices.symmetricKey(Hex.decode(detail.value), template)

                parent.setEncryptor(k.encryptor(algSpec))
            }
            is ScryptDetails -> {
                var pbeSpec = ScryptSpec(detail.saltLength, detail.costParameter, detail.blockSize, detail.parallelization)

                if (template.equals(AESGenSpec.symType) || template.equals(AESGenSpec.authType)) {
                    pbe = KCryptoServices.pbkdf(pbeSpec, AESGenSpec(detail.keySize))
                } else {
                    throw IllegalStateException("unknown key type")
                }
            }
            is PBKDF2Details -> {
                var pbeSpec = PBKDF2Spec(detail.saltLength, detail.iterationCount, detail.prf)

                if (template.equals(AESGenSpec.symType) || template.equals(AESGenSpec.authType)) {
                    pbe = KCryptoServices.pbkdf(pbeSpec, AESGenSpec(detail.keySize))
                } else {
                    throw IllegalStateException("unknown key type")
                }
            }
            else -> throw IllegalStateException("unknown detail type")
        }

        return this
    }

    /**
     * "with" password.
     */
    infix fun with(password: CharArray): EncryptionDetails {

        val kdf = pbe
        if (kdf != null) {
            parent.setEncryptor(kdf.symmetricKey(password).encryptor(algSpec))
        } else {
            throw IllegalStateException("password specified without KDF")
        }

        return this
    }
}

data class key(val value: String)

/**
 * DSL for the definition of S-Crypt parameters.
 */
class ScryptDetails {
    var saltLength = 20
    var costParameter = 1048576
    var blockSize = 8
    var parallelization = 1
    var keySize = 256
}

class PBKDF2Details {
    val sha1 = HMacSHA1GenSpec.authType
    val sha224 = HMacSHA224GenSpec.authType
    val sha256 = HMacSHA256GenSpec.authType

    var saltLength = 20
    var iterationCount = 16384
    var keySize = 256
    var prf = sha1
}

class BasePBKDFDetails {
    var saltLength = 20
    var iterationCount = 16384
    var keySize = 256
}

/**
 * DSL for specifying an encryptor.
 */
class SymmetricEncryptionBlock(private val parent: EncryptedPrivateKeyBody) {

    val encryptor: Encryptor<AlgorithmIdentifier> get() = parent.encryptor()
}