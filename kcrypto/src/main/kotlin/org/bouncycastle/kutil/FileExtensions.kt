package org.bouncycastle.kutil

import KCryptoServices
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.cert.X509CRLHolder
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.kcrypto.DecryptionKey
import org.bouncycastle.kcrypto.Encodable
import org.bouncycastle.kcrypto.KeyPair
import org.bouncycastle.kcrypto.SigningKey
import org.bouncycastle.kcrypto.cert.CRL
import org.bouncycastle.kcrypto.cert.Certificate
import org.bouncycastle.kcrypto.cmp.ProtectedPKIMessage
import org.bouncycastle.kcrypto.cms.CertificateManagementMessage
import org.bouncycastle.kcrypto.cms.SignedData
import org.bouncycastle.kcrypto.crmf.CertificateRequest
import org.bouncycastle.kcrypto.pkcs.PKCS10Request
import org.bouncycastle.kcrypto.pkcs.PKCS8EncryptedPrivateKey
import org.bouncycastle.openssl.MiscPEMGenerator
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemWriter
import java.io.*

/**
 * Write out an object's encoded in PEM format to an OutputStreamWriter.
 *
 * @param obj the object to be PEM encoded.
 */
fun OutputStreamWriter.writePEMObject(obj: Encodable) {
    val pw = PemWriter(this)

    when (obj) {
        is SigningKey -> pw.writeObject(MiscPEMGenerator(PrivateKeyInfo.getInstance(obj.encoding)))
        is DecryptionKey -> pw.writeObject(MiscPEMGenerator(PrivateKeyInfo.getInstance(obj.encoding)))
        is Certificate -> pw.writeObject(MiscPEMGenerator(X509CertificateHolder(obj.encoding)))
        is CertificateRequest -> pw.writeObject(PemObject("CRMF MESSAGE", obj.encoding))
        is ProtectedPKIMessage -> pw.writeObject(PemObject("CMP MESSAGE", obj.encoding))
        is PKCS10Request -> pw.writeObject(MiscPEMGenerator(PKCS10CertificationRequest(obj.encoding)))
        is PKCS8EncryptedPrivateKey -> pw.writeObject(PemObject("ENCRYPTED PRIVATE KEY", obj.encoding))
        is CertificateManagementMessage -> pw.writeObject(PemObject("PKCS7", obj.encoding))
        is SignedData -> pw.writeObject(PemObject("PKCS7", obj.encoding))
        is CRL -> pw.writeObject(MiscPEMGenerator(X509CRLHolder(obj.encoding)))
        else -> throw IllegalArgumentException("unknown object passed for PEM encoding")
    }

    pw.flush()
}


fun <T : Any?> InputStreamReader.readPEMObject(): T? {
    val pr = PEMParser(this)


    val obj = pr.readObject()
    if (obj is PEMKeyPair) {
        val converter = createConverter()

        return KeyPair(converter.getKeyPair(obj)) as T
    }
    if (obj is X509CertificateHolder) {
        return Certificate(obj.encoded) as T
    }
    if (obj is PKCS8EncryptedPrivateKeyInfo) {
        return PKCS8EncryptedPrivateKey(obj.encoded) as T
    }
    return obj as T

}


fun File.writePEMObject(obj: Encodable) {
    var fw = FileWriter(this)

    try {
        fw.writePEMObject(obj)
    }
    finally {
        fw.close()
    }
}

private fun createConverter(): JcaPEMKeyConverter {
    var converter = JcaPEMKeyConverter()
    if (KCryptoServices._provider != null) {
        converter = converter.setProvider(KCryptoServices._provider)
    }

    return converter
}

fun <T : Any?> File.readPEMObject(): T? {
    val pr = PEMParser(FileReader(this))

    try {
        val obj = pr.readObject()
        if (obj is PEMKeyPair) {
            val converter = createConverter()

            return KeyPair(converter.getKeyPair(obj)) as T
        }
        if (obj is X509CertificateHolder) {
            return Certificate(obj.encoded) as T
        }
        if (obj is PKCS8EncryptedPrivateKeyInfo) {
            return PKCS8EncryptedPrivateKey(obj.encoded) as T
        }
        return obj as T
    } finally {
        pr.close()
    }
}






