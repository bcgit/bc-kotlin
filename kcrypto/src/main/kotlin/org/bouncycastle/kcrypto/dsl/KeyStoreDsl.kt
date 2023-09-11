package org.bouncycastle.kcrypto.dsl

import KCryptoServices
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.kcrypto.*
import org.bouncycastle.kcrypto.cert.Certificate
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.*

/**
 * A keystore based key builder.
 */
class KeyStoreBasedKeyBuilder {
    lateinit var keyStore: WrappedKeyStore
    lateinit var alias: String

    var keyPassword: CharArray = "".toCharArray()

    fun signingKey(): SigningKey {
        return BaseSigningKey(keyStore.wrappedKs.getKey(alias, keyPassword) as PrivateKey)
    }

    fun verificationKey(): VerificationKey {
        return BaseVerificationKey(Certificate((keyStore.wrappedKs.getCertificate(alias) as X509Certificate).encoded))
    }
}

/**
 * @return A SigningKey that can be initialized by the block.
 */
fun signingKey(block: KeyStoreBasedKeyBuilder.() -> Unit): SigningKey =
    KeyStoreBasedKeyBuilder().apply(block).signingKey()


/**
 * allows the use of a block to configure a Key Store Builder.
 */
fun KeyStoreBasedKeyBuilder.pkcs12KeyStore(block: KeyStoreBuilder.() -> Unit) {
    keyStore = KeyStoreBuilder("PKCS12").apply(block).build()
}


/**
 * Returns a VerificationKey instance that cna be initialized by the block.
 */
fun verificationKey(block: KeyStoreBasedKeyBuilder.() -> Unit): VerificationKey =
    KeyStoreBasedKeyBuilder().apply(block).verificationKey()

/**
 * Key Store builder DSL.
 * storeName and storePassword
 */
class KeyStoreBuilder(type: String) {
    lateinit var storeName: String
    lateinit var storePassword: CharArray

    private var storeType: String = type

    fun build(): WrappedKeyStore {
        var ks = KeyStore.getInstance(storeType, KCryptoServices._provider)
        
        if (this::storeName.isInitialized && File(storeName).canRead()) {
            ks.load(FileInputStream(storeName), storePassword)
        } else {
            ks.load(null, null)
        }

        return WrappedKeyStore(ks);
    }
}

class KeyStoreBody(storeType: String) {

    val type = storeType

    fun build(): WrappedKeyStore
    {
        var bldr = KeyStoreBuilder(type)

        return bldr.build()
    }
}

class KeyEntryBody
{
    lateinit var alias: String
    lateinit var signingKey: SigningKey
    lateinit var certChain: Array<Certificate>
}

class CertificateEntryBody
{
    lateinit var alias: String
    lateinit var certificate: Certificate
}


class KeyStoreFileBody
{
    lateinit var password: CharArray
    lateinit var fileName: String
}

class WrappedKeyStore(ks: KeyStore): Encodable {

    var wrappedKs = ks

    var password = "".toCharArray();

    infix fun set(keyEntry: KeyEntryBody) {
        val certConv = JcaX509CertificateConverter().setProvider(wrappedKs.provider)

        var x509Chain = Array<X509Certificate>(keyEntry.certChain.size) { i ->
            certConv.getCertificate(keyEntry.certChain[i]._cert)
        }

        wrappedKs.setKeyEntry(keyEntry.alias, (keyEntry.signingKey as BaseSigningKey)._privKey, "".toCharArray(), x509Chain)
    }

    infix fun set(certEntry: CertificateEntryBody) {
        val certConv = JcaX509CertificateConverter().setProvider(wrappedKs.provider)
        
        wrappedKs.setCertificateEntry(certEntry.alias, certConv.getCertificate(certEntry.certificate._cert))
    }

    infix fun delete(alias: String) {
        wrappedKs.deleteEntry(alias)
    }

    infix fun isCertificateEntry(alias: String): Boolean {
        return wrappedKs.isCertificateEntry(alias)
    }

    infix fun isKeyEntry(alias: String): Boolean {
        return wrappedKs.isKeyEntry(alias)
    }

    infix fun store(file: KeyStoreFileBody) {
        var fOut = FileOutputStream(file.fileName)
        wrappedKs.store(fOut, file.password)
    }

    infix fun load(file: KeyStoreFileBody) {
        var fIn = FileInputStream(file.fileName)
        wrappedKs.load(fIn, file.password)
    }
    
    infix fun withPassword(passwd: CharArray): Encodable {
        password = passwd
        return this
    }

    fun encoded(): ByteArray {
        var bOut = ByteArrayOutputStream()
        wrappedKs.store(bOut, password)

        return bOut.toByteArray()
    }

    fun aliases(): Enumeration<String> {
        return wrappedKs.aliases()
    }

    override val encoding: ByteArray
        get() = encoded()
}

fun pkcs12KeyStore(): WrappedKeyStore = KeyStoreBody("PKCS12").build()

fun keyEntry(block: KeyEntryBody.() -> Unit): KeyEntryBody = KeyEntryBody().apply(block)

fun certificateEntry(block: CertificateEntryBody.() -> Unit): CertificateEntryBody = CertificateEntryBody().apply(block)

fun file(block: KeyStoreFileBody.() -> Unit): KeyStoreFileBody = KeyStoreFileBody().apply(block)