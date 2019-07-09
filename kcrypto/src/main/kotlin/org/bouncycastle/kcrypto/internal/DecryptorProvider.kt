package org.bouncycastle.kcrypto.internal

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PBES2Parameters
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.Decryptor
import org.bouncycastle.kcrypto.SymmetricKey
import org.bouncycastle.kcrypto.spec.KeyGenSpec
import org.bouncycastle.kcrypto.spec.SymAlgSpec
import org.bouncycastle.kcrypto.spec.symmetric.AESGenSpec
import org.bouncycastle.kcrypto.spec.symmetric.CCMSpec
import org.bouncycastle.kcrypto.spec.symmetric.GCMSpec
import org.bouncycastle.kcrypto.spec.symmetric.KWPSpec
import java.io.InputStream

internal fun findSymSpec(algId: AlgorithmIdentifier): SymAlgSpec<AlgorithmIdentifier> = when (algId.algorithm) {
    NISTObjectIdentifiers.id_aes128_GCM,
    NISTObjectIdentifiers.id_aes192_GCM,
    NISTObjectIdentifiers.id_aes256_GCM -> GCMSpec(algId)
    NISTObjectIdentifiers.id_aes128_CCM,
    NISTObjectIdentifiers.id_aes192_CCM,
    NISTObjectIdentifiers.id_aes256_CCM -> CCMSpec(algId)
    NISTObjectIdentifiers.id_aes128_wrap_pad,
    NISTObjectIdentifiers.id_aes192_wrap_pad,
    NISTObjectIdentifiers.id_aes256_wrap_pad -> KWPSpec(algId)
    PKCSObjectIdentifiers.id_PBES2 -> findSymSpec(
            AlgorithmIdentifier.getInstance(PBES2Parameters.getInstance(algId.parameters).encryptionScheme))
    else -> throw IllegalArgumentException("unknown algorithm: " + algId.algorithm)
}

internal fun findSymKeyGenSpec(algId: AlgorithmIdentifier): KeyGenSpec = when (algId.algorithm) {
    NISTObjectIdentifiers.id_aes128_CCM,
    NISTObjectIdentifiers.id_aes128_GCM,
    NISTObjectIdentifiers.id_aes128_wrap_pad-> AESGenSpec(128)
    NISTObjectIdentifiers.id_aes192_CCM,
    NISTObjectIdentifiers.id_aes192_GCM,
    NISTObjectIdentifiers.id_aes192_wrap_pad -> AESGenSpec(192)
    NISTObjectIdentifiers.id_aes256_CCM,
    NISTObjectIdentifiers.id_aes256_GCM,
    NISTObjectIdentifiers.id_aes256_wrap_pad -> AESGenSpec(256)
    else -> throw IllegalArgumentException("unknown algorithm: " + algId.algorithm)
}

internal class DecryptorProviderImpl(private val key: SymmetricKey) : org.bouncycastle.operator.InputDecryptorProvider {

    override fun get(algId: AlgorithmIdentifier): org.bouncycastle.operator.InputDecryptor {

        return InputDecryptorImpl(key.decryptor(findSymSpec(algId)))
    }
}

internal class InputDecryptorImpl(private val decryptor: Decryptor<AlgorithmIdentifier>) : org.bouncycastle.operator.InputDecryptor {
    override fun getInputStream(baseStream: InputStream): InputStream {
        return decryptor.inputDecryptor(baseStream).decStream
    }

    override fun getAlgorithmIdentifier(): AlgorithmIdentifier {
        return decryptor.algorithmIdentifier
    }
}