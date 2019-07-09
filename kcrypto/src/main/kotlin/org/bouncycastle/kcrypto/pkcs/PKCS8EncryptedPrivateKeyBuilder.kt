package org.bouncycastle.kcrypto.pkcs

import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.Encryptor
import org.bouncycastle.kcrypto.PrivateKey
import java.io.ByteArrayOutputStream
import java.io.IOException

class PKCS8EncryptedPrivateKeyBuilder(private val privateKeyInfo: PrivateKeyInfo)
{
    constructor(privateKeyInfo: ByteArray) : this(PrivateKeyInfo.getInstance(privateKeyInfo))

    constructor(privateKey: PrivateKey) : this(privateKey.encoding)

    fun build(encryptor: Encryptor<AlgorithmIdentifier>): PKCS8EncryptedPrivateKey {
        try {
            val bOut = ByteArrayOutputStream()
            val outEnc = encryptor.outputEncryptor(bOut)

            outEnc.use {
                it.encStream.write(privateKeyInfo.encoded)
            }

            return PKCS8EncryptedPrivateKey(EncryptedPrivateKeyInfo(outEnc.algorithmIdentifier, bOut.toByteArray()))
        } catch (e: IOException) {
            throw IllegalStateException("cannot encode privateKeyInfo")
        }
    }
}