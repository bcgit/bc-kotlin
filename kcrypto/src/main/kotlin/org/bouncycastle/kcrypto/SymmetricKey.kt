package org.bouncycastle.kcrypto

import KCryptoServices
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.pkcs.EncryptionScheme
import org.bouncycastle.asn1.pkcs.KeyDerivationFunc
import org.bouncycastle.asn1.pkcs.PBES2Parameters
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.jcajce.io.CipherOutputStream
import org.bouncycastle.kcrypto.spec.AEADAlgSpec
import org.bouncycastle.kcrypto.spec.AlgSpec
import org.bouncycastle.kcrypto.spec.SymAlgSpec
import org.bouncycastle.kcrypto.spec.symmetric.CCMSpec
import org.bouncycastle.kcrypto.spec.symmetric.GCMSpec
import org.bouncycastle.kcrypto.spec.symmetric.KWPSpec
import org.bouncycastle.util.io.Streams
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.AlgorithmParameters
import java.security.Key
import java.security.PrivateKey
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.SecretKey

private fun findAlgorithm(algSpec: AlgSpec<AlgorithmIdentifier>): String = when (algSpec) {
    is GCMSpec -> "GCM"
    is CCMSpec -> "CCM"
    is KWPSpec -> "AESKWP"
    else -> throw IllegalArgumentException("unknown AlgSpec")
}

private fun createAlgID(algSpec: AlgSpec<AlgorithmIdentifier>, params: AlgorithmParameters?): AlgorithmIdentifier {
    var algOid = algSpec.algorithmIdentifier.algorithm;

    // TODO: check that absent is handled correctly...
    if (params != null) {
        return AlgorithmIdentifier(algOid, ASN1Primitive.fromByteArray(params.encoded))
    } else {
        // AESKWP meant to be absent.
        return AlgorithmIdentifier(algOid)
    }
}

private class AeadOutputStream(val c: Cipher) : OutputStream() {
    override fun write(buf: ByteArray) {
        c.updateAAD(buf)
    }

    override fun write(buf: ByteArray, off: Int, len: Int) {
        c.updateAAD(buf, off, len)
    }

    override fun write(b: Int) {
        c.updateAAD(byteArrayOf(b.toByte()))
    }
}

private class SymKeyWrapper(algSpec: AlgSpec<AlgorithmIdentifier>, key: Key) : KeyWrapper<AlgorithmIdentifier> {

    override val algorithmIdentifier: AlgorithmIdentifier

    private val cipher: Cipher

    init {
        val algorithm = findAlgorithm(algSpec)

        cipher = KCryptoServices.helper.createCipher(algorithm)

        if (algSpec is GCMSpec || algSpec is CCMSpec) {
            var p = KCryptoServices.helper.createAlgorithmParameters(algorithm)
            var algorithmIdentifier = algSpec.algorithmIdentifier
            p.init(algorithmIdentifier.parameters.toASN1Primitive().encoded)

            cipher.init(Cipher.WRAP_MODE, key, p)
        } else {
            cipher.init(Cipher.WRAP_MODE, key)
        }

        algorithmIdentifier = createAlgID(algSpec, cipher.parameters)
    }

    override fun wrap(key: SymmetricKey): ByteArray {
        return cipher.wrap((key as BaseSymmetricKey)._key)
    }

    override fun wrap(key: SigningKey): ByteArray {
        return cipher.wrap((key as BaseSigningKey).privKey)
    }
}

private class SymKeyUnwrapper(private val algSpec: AlgSpec<AlgorithmIdentifier>, private val key: Key) : KeyUnwrapper<AlgorithmIdentifier> {

    override val algorithmIdentifier: AlgorithmIdentifier

    private val cipher: Cipher

    init {
        val algorithm = findAlgorithm(algSpec)

        cipher = KCryptoServices.helper.createCipher(algorithm)

        if (algSpec is GCMSpec || algSpec is CCMSpec) {
            var p = KCryptoServices.helper.createAlgorithmParameters(algorithm)

            p.init(algSpec.algorithmIdentifier.parameters.toASN1Primitive().encoded)

            cipher.init(Cipher.UNWRAP_MODE, key, p)
        } else {
            cipher.init(Cipher.UNWRAP_MODE, key)
        }

        algorithmIdentifier = createAlgID(algSpec, cipher.parameters)
    }

    private fun initCipher(algorithm: String): Int {
        val mode: Int
        if (algorithm.equals("Decryption") || algorithm.equals("Signing")) {
            mode = Cipher.DECRYPT_MODE
        } else {
            mode = Cipher.UNWRAP_MODE
        }

        if (algSpec is GCMSpec || algSpec is CCMSpec) {
            var p = KCryptoServices.helper.createAlgorithmParameters(algorithm)

            p.init(algSpec.algorithmIdentifier.parameters.toASN1Primitive().encoded)

            cipher.init(mode, key, p)
        } else {
            cipher.init(mode, key)
        }

        return mode
    }

    override fun unwrap(wrappedKey: ByteArray, keyTemplate: KeyType<SymmetricKey>): SymmetricKey {

        cipher.init(Cipher.UNWRAP_MODE, key)
        val secretKey = cipher.unwrap(wrappedKey, keyTemplate.algorithm, Cipher.SECRET_KEY) as SecretKey
        return BaseSymmetricKey(secretKey.encoded.size * 8, secretKey)
    }

    override fun unwrap(wrappedKey: ByteArray, keyTemplate: KeyType<SigningKey>): SigningKey {

        var mode = initCipher(keyTemplate.algorithm)

        if (mode == Cipher.DECRYPT_MODE)
        {
            return KCryptoServices.signingKey(cipher.doFinal(wrappedKey), keyTemplate)
        }
        return BaseSigningKey(cipher.unwrap(wrappedKey, keyTemplate.algorithm, Cipher.PRIVATE_KEY) as PrivateKey)
    }

    override fun unwrap(wrappedKey: ByteArray, keyTemplate: KeyType<DecryptionKey>): DecryptionKey {

        var mode = initCipher(keyTemplate.algorithm)
        if (mode == Cipher.DECRYPT_MODE)
        {
            return KCryptoServices.decryptionKey(cipher.doFinal(wrappedKey), keyTemplate)
        }

        return BaseDecryptionKey(cipher.unwrap(wrappedKey, keyTemplate.algorithm, Cipher.PRIVATE_KEY) as PrivateKey)
    }
}

private class AeadEncryptor(algSpec: AlgSpec<AlgorithmIdentifier>, parent: SymmetricKey, key: Key) : AEADEncryptor<AlgorithmIdentifier> {

    private val algorithmIdentifier: AlgorithmIdentifier
    private val c: Cipher

    init {
        val algorithm = findAlgorithm(algSpec)

        c = KCryptoServices.helper.createCipher(algorithm)
        var p = KCryptoServices.helper.createAlgorithmParameters(algorithm)

        p.init(algSpec.algorithmIdentifier.parameters.toASN1Primitive().encoded)

        c.init(Cipher.ENCRYPT_MODE, key, p)

        val baseAlgID = createAlgID(algSpec, c.parameters)

        if (parent is PBESymmetricKey)
        {
            var pbsParams = PBES2Parameters(parent.keyDerivationFunc, EncryptionScheme.getInstance(baseAlgID))
            algorithmIdentifier = AlgorithmIdentifier(parent.pbeAlg, pbsParams)
        } else {
            algorithmIdentifier = baseAlgID
        }
    }

    override fun outputEncryptor(destStream: OutputStream): OutputAEADEncryptor<AlgorithmIdentifier> {
        return OutputAeadEncryptor(algorithmIdentifier, CipherOutputStream(destStream, c), AeadOutputStream(c))
    }
}

private class OutputAeadEncryptor(override val algorithmIdentifier: AlgorithmIdentifier,
                                  override val encStream: OutputStream,
                                  override val aadStream: OutputStream) : OutputAEADEncryptor<AlgorithmIdentifier> {

    override fun close() {
        aadStream.close()
        encStream.close()
    }
}

private class AeadDecryptor(algSpec: AlgSpec<AlgorithmIdentifier>, key: Key) : AEADDecryptor<AlgorithmIdentifier> {

    override val algorithmIdentifier: AlgorithmIdentifier
    private val c: Cipher

    init {
        var algorithm: String
        var parameters: ByteArray
        
        algorithm = findAlgorithm(algSpec)
        parameters = algSpec.algorithmIdentifier.parameters.toASN1Primitive().encoded

        c = KCryptoServices.helper.createCipher(algorithm)
        var p = KCryptoServices.helper.createAlgorithmParameters(algorithm)

        p.init(parameters)

        c.init(Cipher.DECRYPT_MODE, key, p)

        algorithmIdentifier = createAlgID(algSpec, c.parameters)
    }

    override fun outputDecryptor(destStream: OutputStream): OutputAEADDecryptor<AlgorithmIdentifier> {

        return OutputAeadDecryptor(algorithmIdentifier, CipherOutputStream(destStream, c), AeadOutputStream(c))
    }

    override fun inputDecryptor(sourceStream: InputStream): InputAEADDecryptor<AlgorithmIdentifier> {
        return InputAeadDecryptor(algorithmIdentifier, CipherInputStream(sourceStream, c), AeadOutputStream(c))
    }
}

private class OutputAeadDecryptor(override val algorithmIdentifier: AlgorithmIdentifier,
                                  override val decStream: OutputStream,
                                  override val aadStream: OutputStream) : OutputAEADDecryptor<AlgorithmIdentifier> {
    override fun close() {
        aadStream.close()
        decStream.close()
    }
}

private class InputAeadDecryptor(override val algorithmIdentifier: AlgorithmIdentifier,
                                  override val decStream: InputStream,
                                  override val aadStream: OutputStream) : InputAEADDecryptor<AlgorithmIdentifier> {
    override fun close() {
        aadStream.close()
        decStream.close()
    }
}

private class BaseSymmetricEncryptor(algSpec: SymAlgSpec<AlgorithmIdentifier>, parent: SymmetricKey, key: SecretKey) : Encryptor<AlgorithmIdentifier> {

    private val algorithmIdentifier: AlgorithmIdentifier
    private val c: Cipher

    private val isKeyWrap: Boolean

    init {
        val algorithm = findAlgorithm(algSpec)

        c = KCryptoServices.helper.createCipher(algorithm)

        var baseAlgID: AlgorithmIdentifier

        isKeyWrap = "AESKWP".equals(algorithm)

        if (isKeyWrap) {
            c.init(Cipher.ENCRYPT_MODE, key)

            baseAlgID = createAlgID(algSpec, null)
        } else {
            var p = KCryptoServices.helper.createAlgorithmParameters(algorithm)

            p.init(algSpec.algorithmIdentifier.parameters.toASN1Primitive().encoded)

            c.init(Cipher.ENCRYPT_MODE, key, p)

            baseAlgID = createAlgID(algSpec, c.parameters)
        }

        if (parent is PBESymmetricKey)
        {
            var pbsParams = PBES2Parameters(parent.keyDerivationFunc, EncryptionScheme.getInstance(baseAlgID))
            algorithmIdentifier = AlgorithmIdentifier(parent.pbeAlg, pbsParams)
        } else {
            algorithmIdentifier = baseAlgID
        }
    }

    override fun outputEncryptor(destStream: OutputStream): OutputEncryptor<AlgorithmIdentifier> {
        if (isKeyWrap) { // work around for bug in FIPS module
            return ByteArrayOutputEncryptor(algorithmIdentifier, destStream, c)
        } else {
            return BaseOutputEncryptor(algorithmIdentifier, CipherOutputStream(destStream, c))
        }
    }
}

private class BaseOutputEncryptor(override val algorithmIdentifier: AlgorithmIdentifier,
                                  override val encStream: OutputStream) : OutputEncryptor<AlgorithmIdentifier> {

    override fun close() {
        encStream.close()
    }
}

private class ByteArrayOutputEncryptor(override val algorithmIdentifier: AlgorithmIdentifier, private val destStream: OutputStream, private val c: Cipher) : OutputEncryptor<AlgorithmIdentifier> {

    override val encStream: OutputStream = ByteArrayOutputStream()

    override fun close() {
        encStream.close()

        destStream.write(c.doFinal((encStream as ByteArrayOutputStream).toByteArray()))
    }
}

private class BaseSymmetricDecryptor(algSpec: AlgSpec<AlgorithmIdentifier>, key: Key) : Decryptor<AlgorithmIdentifier> {

    override val algorithmIdentifier: AlgorithmIdentifier
    private val c: Cipher

    private val isKeyWrap: Boolean

    init {
        var algorithm: String

        algorithm = findAlgorithm(algSpec)

        c = KCryptoServices.helper.createCipher(algorithm)

        isKeyWrap = "AESKWP".equals(algorithm)

        if (isKeyWrap) {
            c.init(Cipher.DECRYPT_MODE, key)
        } else {
            var p = KCryptoServices.helper.createAlgorithmParameters(algorithm)
            var parameters = algSpec.algorithmIdentifier.parameters.toASN1Primitive().encoded

            p.init(parameters)

            c.init(Cipher.DECRYPT_MODE, key, p)
        }

        algorithmIdentifier = createAlgID(algSpec, c.parameters)
    }

    override fun outputDecryptor(destStream: OutputStream): OutputDecryptor<AlgorithmIdentifier> {
        if (isKeyWrap) { // work around for FIPS bug
            return ByteArrayOutputDecryptor(algorithmIdentifier, destStream, c)
        } else {
            return BaseOutputDecryptor(algorithmIdentifier, CipherOutputStream(destStream, c))
        }
    }

    override fun inputDecryptor(sourceStream: InputStream): InputDecryptor<AlgorithmIdentifier> {
        if (isKeyWrap) {
            return ByteArrayInputDecryptor(algorithmIdentifier, sourceStream, c)
        } else {
            return BaseInputDecryptor(algorithmIdentifier, CipherInputStream(sourceStream, c))
        }
    }
}

private class ByteArrayOutputDecryptor(override val algorithmIdentifier: AlgorithmIdentifier, private val destStream: OutputStream, private val c: Cipher) : OutputDecryptor<AlgorithmIdentifier> {

    override val decStream: OutputStream = ByteArrayOutputStream()

    override fun close() {
        decStream.close()

        destStream.write(c.doFinal((decStream as ByteArrayOutputStream).toByteArray()))
    }
}

private class BaseOutputDecryptor(override val algorithmIdentifier: AlgorithmIdentifier,
                                  override val decStream: OutputStream) : OutputDecryptor<AlgorithmIdentifier> {
    override fun close() {
        decStream.close()
    }
}

private class ByteArrayInputDecryptor(override val algorithmIdentifier: AlgorithmIdentifier, private val sourceStream: InputStream, private val c: Cipher) : InputDecryptor<AlgorithmIdentifier> {

    override val decStream: InputStream = ByteArrayInputStream(c.doFinal(Streams.readAll(sourceStream)))

    override fun close() {
        sourceStream.close()
    }
}

private class BaseInputDecryptor(override val algorithmIdentifier: AlgorithmIdentifier,
                                  override val decStream: InputStream) : InputDecryptor<AlgorithmIdentifier> {
    override fun close() {
        decStream.close()
    }
}

internal class BaseSymmetricKey(override val size: Int, internal val _key: SecretKey) : SymmetricKey {
    
    override val encoding: ByteArray
        get() = _key.encoded
    
    override fun keyWrapper(algSpec: AlgSpec<AlgorithmIdentifier>): KeyWrapper<AlgorithmIdentifier> {
        return SymKeyWrapper((algSpec as SymAlgSpec).validatedSpec(this), _key)
    }

    override fun keyUnwrapper(algSpec: AlgSpec<AlgorithmIdentifier>): KeyUnwrapper<AlgorithmIdentifier> {
        return SymKeyUnwrapper((algSpec as SymAlgSpec).validatedSpec(this), _key)
    }

    override fun encryptor(algSpec: AEADAlgSpec<AlgorithmIdentifier>): AEADEncryptor<AlgorithmIdentifier> {
        return AeadEncryptor(algSpec.validatedSpec(this), this, _key)
    }

    override fun decryptor(algSpec: AEADAlgSpec<AlgorithmIdentifier>): AEADDecryptor<AlgorithmIdentifier> {
        return AeadDecryptor(algSpec.validatedSpec(this), _key)
    }

    override fun encryptor(algSpec: AlgSpec<AlgorithmIdentifier>): Encryptor<AlgorithmIdentifier> {
        return BaseSymmetricEncryptor((algSpec as SymAlgSpec).validatedSpec(this), this, _key)
    }

    override fun decryptor(algSpec: AlgSpec<AlgorithmIdentifier>): Decryptor<AlgorithmIdentifier> {
        return BaseSymmetricDecryptor((algSpec as SymAlgSpec).validatedSpec(this), _key)
    }
}

internal class PBESymmetricKey(override val size: Int, private val key: SecretKey, internal val pbeAlg: ASN1ObjectIdentifier, internal val keyDerivationFunc: KeyDerivationFunc) : SymmetricKey {

    override val encoding: ByteArray
        get() = key.encoded

    override fun keyWrapper(algSpec: AlgSpec<AlgorithmIdentifier>): KeyWrapper<AlgorithmIdentifier> {
        return SymKeyWrapper((algSpec as SymAlgSpec).validatedSpec(this), key)
    }

    override fun keyUnwrapper(algSpec: AlgSpec<AlgorithmIdentifier>): KeyUnwrapper<AlgorithmIdentifier> {
        return SymKeyUnwrapper((algSpec as SymAlgSpec).validatedSpec(this), key)
    }

    override fun encryptor(algSpec: AEADAlgSpec<AlgorithmIdentifier>): AEADEncryptor<AlgorithmIdentifier> {
        return AeadEncryptor(algSpec.validatedSpec(this), this, key)
    }

    override fun decryptor(algSpec: AEADAlgSpec<AlgorithmIdentifier>): AEADDecryptor<AlgorithmIdentifier> {
        return AeadDecryptor(algSpec.validatedSpec(this), key)
    }

    override fun encryptor(algSpec: AlgSpec<AlgorithmIdentifier>): Encryptor<AlgorithmIdentifier> {
        return BaseSymmetricEncryptor((algSpec as SymAlgSpec).validatedSpec(this), this, key)
    }

    override fun decryptor(algSpec: AlgSpec<AlgorithmIdentifier>): Decryptor<AlgorithmIdentifier> {
        return BaseSymmetricDecryptor((algSpec as SymAlgSpec).validatedSpec(this), key)
    }
}

/**
 * Operational interface for a symmetric cipher key.
 */
interface SymmetricKey : WrappingKey, UnwrappingKey, Encodable {

    /**
     * Size of the key in bits.
     */
    val size: Int

    fun encryptor(algSpec: AEADAlgSpec<AlgorithmIdentifier>): AEADEncryptor<AlgorithmIdentifier>

    fun decryptor(algSpec: AEADAlgSpec<AlgorithmIdentifier>): AEADDecryptor<AlgorithmIdentifier>

    fun encryptor(algSpec: AlgSpec<AlgorithmIdentifier>): Encryptor<AlgorithmIdentifier>

    fun decryptor(algSpec: AlgSpec<AlgorithmIdentifier>): Decryptor<AlgorithmIdentifier>
}