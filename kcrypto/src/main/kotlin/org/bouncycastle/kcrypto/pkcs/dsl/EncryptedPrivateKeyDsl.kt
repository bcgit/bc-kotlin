package org.bouncycastle.kcrypto.pkcs.dsl

import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.Encryptor
import org.bouncycastle.kcrypto.PrivateKey
import org.bouncycastle.kcrypto.dsl.EncryptionDetails
import org.bouncycastle.kcrypto.dsl.PBKDF2Details
import org.bouncycastle.kcrypto.dsl.ScryptDetails
import org.bouncycastle.kcrypto.dsl.SymmetricEncryptionBlock
import org.bouncycastle.kcrypto.pkcs.PKCS8EncryptedPrivateKey
import org.bouncycastle.kcrypto.pkcs.PKCS8EncryptedPrivateKeyBuilder
import org.bouncycastle.kcrypto.spec.symmetric.AESGenSpec
import org.bouncycastle.kcrypto.spec.symmetric.CCMSpec
import org.bouncycastle.kcrypto.spec.symmetric.GCMSpec
import org.bouncycastle.kcrypto.spec.symmetric.KWPSpec

/**
 * DLS for an encrypted private key body.
 */
class EncryptedPrivateKeyBody {

    val AESGCM = EncryptionDetails(this, AESGenSpec.symType, GCMSpec())
    val AESCCM = EncryptionDetails(this, AESGenSpec.symType, CCMSpec())
    val AESKWP = EncryptionDetails(this, AESGenSpec.symType, KWPSpec())

    fun SCRYPT(block: ScryptDetails.()-> Unit) = ScryptDetails().apply(block)

    fun PBKDF2(block: PBKDF2Details.()-> Unit) = PBKDF2Details().apply(block)

    lateinit var privateKey: PrivateKey

    private val encryption = SymmetricEncryptionBlock(this)

    private lateinit var encryptor: Encryptor<AlgorithmIdentifier>

    fun encryptor(): Encryptor<AlgorithmIdentifier> {
        return encryptor
    }

    fun build(): PKCS8EncryptedPrivateKey {

       var bldr = PKCS8EncryptedPrivateKeyBuilder(privateKey.encoding)

        return bldr.build(encryption.encryptor)
    }

    fun encryption(block: SymmetricEncryptionBlock.() -> Unit) = encryption.apply(block)

    fun setEncryptor(encryptor: Encryptor<AlgorithmIdentifier>) {
        this.encryptor = encryptor
    }
}

fun encryptedPrivateKey(block: EncryptedPrivateKeyBody.()-> Unit): PKCS8EncryptedPrivateKey = EncryptedPrivateKeyBody().apply(block).build()

