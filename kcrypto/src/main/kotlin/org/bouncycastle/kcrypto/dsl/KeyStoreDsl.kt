package org.bouncycastle.kcrypto.dsl

import KCryptoServices
import org.bouncycastle.kcrypto.BaseSigningKey
import org.bouncycastle.kcrypto.BaseVerificationKey
import org.bouncycastle.kcrypto.SigningKey
import org.bouncycastle.kcrypto.VerificationKey
import org.bouncycastle.kcrypto.cert.Certificate
import java.io.FileInputStream
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate

/**
 * A keystore based key builder.
 */
class KeyStoreBasedKeyBuilder {
    lateinit var keyStore: KeyStore
    lateinit var alias: String

    var keyPassword: CharArray = "".toCharArray()

    fun signingKey(): SigningKey {
        return BaseSigningKey(keyStore.getKey(alias, keyPassword) as PrivateKey)
    }

    fun verificationKey(): VerificationKey {
        return BaseVerificationKey(Certificate((keyStore.getCertificate(alias) as X509Certificate).encoded))
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
fun KeyStoreBasedKeyBuilder.keyStore(block: KeyStoreBuilder.() -> Unit) {
    keyStore = KeyStoreBuilder().apply(block).build()
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
class KeyStoreBuilder {
    lateinit var storeName: String
    lateinit var storePassword: CharArray

    var storeType: String = "BCFKS"

    fun build(): KeyStore {
        var ks = KeyStore.getInstance(storeType, KCryptoServices._provider)

        ks.load(FileInputStream(storeName), storePassword)

        return ks;
    }
}
