package org.bouncycastle.kcrypto

import KCryptoServices
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder
import org.bouncycastle.util.Arrays
import java.io.IOException
import java.io.OutputStream
import java.security.MessageDigest

internal class BaseDigestVerifier(algorithmName: String, private val _algorithmIdentifier: AlgorithmIdentifier) : DigestVerifier<AlgorithmIdentifier>
{
    val digest: MessageDigest

    override val algorithmIdentifier: AlgorithmIdentifier
        get() = _algorithmIdentifier

    override val stream: OutputStream

    override fun verify(expected: ByteArray): Boolean {
        var d = (stream as DigestOutputStream).digest

        return Arrays.constantTimeAreEqual(d, expected)
    }

    init {
        digest = KCryptoServices.helper.createDigest(algorithmName)

        stream = DigestOutputStream(digest)
    }
}

internal class BaseDigestCalculator(algorithmName: String, private val _algorithmIdentifier: AlgorithmIdentifier) : DigestCalculator<AlgorithmIdentifier>
{
    val digest: MessageDigest

    override val algorithmIdentifier: AlgorithmIdentifier
        get() = _algorithmIdentifier

    override val stream: OutputStream

    override fun digest(): ByteArray {
        return (stream as DigestOutputStream).digest
    }

    init {
        digest = KCryptoServices.helper.createDigest(algorithmName)

        stream = DigestOutputStream(digest)
    }

    override fun close() {
        stream.close()
    }
}

private class DigestOutputStream internal constructor(private val dig: MessageDigest) : OutputStream() {

    private var isClosed: Boolean = false

    internal val digest: ByteArray
        get() {
            if (!isClosed) {
                throw IllegalStateException("attempt to call digest() without closing stream")
            }
            return dig.digest()
        }

    @Throws(IOException::class)
    override fun write(bytes: ByteArray, off: Int, len: Int) {
        dig.update(bytes, off, len)
    }

    @Throws(IOException::class)
    override fun write(bytes: ByteArray) {
        dig.update(bytes)
    }

    @Throws(IOException::class)
    override fun write(b: Int) {
        dig.update(b.toByte())
    }

    @Throws(IOException::class)
    override fun close() {
        super.close()
        isClosed = true
    }
}

internal class BaseDigest(override val algorithmName: String, private val algorithmIdentifier: AlgorithmIdentifier) : Digest
{
    override fun digestVerifier(): DigestVerifier<AlgorithmIdentifier> {
        return BaseDigestVerifier(algorithmName, algorithmIdentifier)
    }

    override fun digestCalculator(): DigestCalculator<AlgorithmIdentifier> {
        return BaseDigestCalculator(algorithmName, algorithmIdentifier)
    }
}


interface Digest
{
    val algorithmName: String

    fun digestCalculator(): DigestCalculator<AlgorithmIdentifier>

    fun digestVerifier(): DigestVerifier<AlgorithmIdentifier>

    companion object
    {
        val defDigestLookup = DefaultDigestAlgorithmIdentifierFinder()

        val SHA1: Digest = BaseDigest("SHA-1", defDigestLookup.find("SHA-1"))
        val SHA224: Digest = BaseDigest("SHA-224", defDigestLookup.find("SHA-224"))
        val SHA256: Digest = BaseDigest("SHA-256", defDigestLookup.find("SHA-256"))
        val SHA384: Digest = BaseDigest("SHA-384", defDigestLookup.find("SHA-384"))
        val SHA512: Digest = BaseDigest("SHA-512", defDigestLookup.find("SHA-512"))
        val SM3: Digest = BaseDigest("SM3", defDigestLookup.find("SM3"))
    }
}