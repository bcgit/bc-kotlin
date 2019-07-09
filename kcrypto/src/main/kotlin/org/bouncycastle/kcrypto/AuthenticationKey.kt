package org.bouncycastle.kcrypto

import KCryptoServices
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.spec.MacAlgSpec
import org.bouncycastle.kcrypto.spec.kdf.findPrfAlgId
import org.bouncycastle.kcrypto.spec.symmetric.CCMSpec
import org.bouncycastle.kcrypto.spec.symmetric.CMACSpec
import org.bouncycastle.util.Arrays
import java.io.IOException
import java.io.OutputStream
import java.security.AlgorithmParameters
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Mac
import javax.crypto.SecretKey

internal class BaseMacVerifier(key: AuthenticationKey, secretKey: SecretKey, macAlgSpec: MacAlgSpec<AlgorithmIdentifier>) : MacVerifier<AlgorithmIdentifier>
{
    val mac: Mac
    val _algorithmId: AlgorithmIdentifier?
    
    override val algorithmIdentifier: AlgorithmIdentifier
        get() = if (_algorithmId != null) _algorithmId else throw IllegalStateException("no algorithmIdentifer available")

    override val stream: OutputStream

    override fun verifies(expected: ByteArray): Boolean {
        var d = (stream as MacOutputStream).doFinal

        return Arrays.constantTimeAreEqual(d, expected)
    }

    init {
        val algName = when (macAlgSpec) {
            is CMACSpec -> "CMAC"
            is CCMSpec -> "CCM"
            else -> throw IllegalArgumentException("unknown MAC algorithm")
        }

        mac = KCryptoServices.helper.createMac(algName)
        
        if (!algName.equals("CMAC")) {
            _algorithmId = macAlgSpec.validatedSpec(key).algorithmIdentifier
            val pGen = AlgorithmParameters.getInstance(algName);

            pGen.init(_algorithmId.parameters.toASN1Primitive().encoded)

            mac.init(secretKey, pGen.getParameterSpec(AlgorithmParameterSpec::class.java))
        } else {
            _algorithmId = null
            mac.init(secretKey)
        }

        stream = MacOutputStream(mac)
    }

    override fun close() {
        stream.close()
    }
}

internal class BaseMacCalculator(key: AuthenticationKey, secretKey: SecretKey, macAlgSpec: MacAlgSpec<AlgorithmIdentifier>) : MacCalculator<AlgorithmIdentifier>
{
    val mac: Mac
    val _algorithmId: AlgorithmIdentifier?

    override val algorithmIdentifier: AlgorithmIdentifier
        get() = if (_algorithmId != null) _algorithmId else throw IllegalStateException("no algorithmIdentifer available")

    override val stream: OutputStream

    override fun mac(): ByteArray {
        return (stream as MacOutputStream).doFinal
    }

    init {
        val algName = when (macAlgSpec) {
            is CMACSpec -> "CMAC"
            is CCMSpec -> "CCM"
            else -> throw IllegalArgumentException("unknown MAC algorithm")
        }

        mac = KCryptoServices.helper.createMac(algName)

        if (!algName.equals("CMAC")) {
            _algorithmId = macAlgSpec.validatedSpec(key).algorithmIdentifier
            val pGen = AlgorithmParameters.getInstance(algName);

            pGen.init(_algorithmId.parameters.toASN1Primitive().encoded)
            
            mac.init(secretKey, pGen.getParameterSpec(AlgorithmParameterSpec::class.java))
        } else {
            _algorithmId = null
            mac.init(secretKey)
        }

        stream = MacOutputStream(mac)
    }

    override fun close() {
        stream.close()
    }
}

internal class BaseHMacVerifier(secretKey: SecretKey, private val _algorithmIdentifier: AlgorithmIdentifier) : MacVerifier<AlgorithmIdentifier>
{
    val mac: Mac

    override val algorithmIdentifier: AlgorithmIdentifier
        get() = _algorithmIdentifier

    override val stream: OutputStream

    override fun verifies(expected: ByteArray): Boolean {
        var d = (stream as MacOutputStream).doFinal

        return Arrays.constantTimeAreEqual(d, expected)
    }

    init {
        mac = KCryptoServices.helper.createMac(secretKey.algorithm)

        mac.init(secretKey)

        stream = MacOutputStream(mac)
    }

    override fun close() {
        stream.close()
    }
}

internal class BaseHMacCalculator(secretKey: SecretKey, private val _algorithmIdentifier: AlgorithmIdentifier) : MacCalculator<AlgorithmIdentifier>
{
    val mac: Mac

    override val algorithmIdentifier: AlgorithmIdentifier
        get() = _algorithmIdentifier

    override val stream: OutputStream

    override fun mac(): ByteArray {
        return (stream as MacOutputStream).doFinal
    }

    init {
        mac = KCryptoServices.helper.createMac(secretKey.algorithm)

        mac.init(secretKey)

        stream = MacOutputStream(mac)
    }

    override fun close() {
        stream.close()
    }
}

private class MacOutputStream internal constructor(private val mac: Mac) : OutputStream() {

    private var isClosed: Boolean = false

    internal val doFinal: ByteArray
        get() {
            if (!isClosed) {
                throw IllegalStateException("attempt to call mac() without closing stream")
            }
            return mac.doFinal()
        }

    @Throws(IOException::class)
    override fun write(bytes: ByteArray, off: Int, len: Int) {
        mac.update(bytes, off, len)
    }

    @Throws(IOException::class)
    override fun write(bytes: ByteArray) {
        mac.update(bytes)
    }

    @Throws(IOException::class)
    override fun write(b: Int) {
        mac.update(b.toByte())
    }

    @Throws(IOException::class)
    override fun close() {
        super.close()
        isClosed = true
    }
}

internal class BaseMacKey(override val size: Int, private val secretKey: SecretKey, private val keyType: KeyType<out Any>): AuthenticationKey
{
    override fun macCalculator(macAlgSpec: MacAlgSpec<AlgorithmIdentifier>): MacCalculator<AlgorithmIdentifier>
    {
        return BaseMacCalculator(this,  secretKey, macAlgSpec)
    }

    override fun macVerifier(macAlgSpec: MacAlgSpec<AlgorithmIdentifier>): MacVerifier<AlgorithmIdentifier>
    {
        return BaseMacVerifier(this, secretKey, macAlgSpec)
    }
}

internal class BaseHMacKey(override val size: Int, private val secretKey: SecretKey, internal val prfType: KeyType<out Any>) : AuthenticationKey
{
    override fun macCalculator(macAlgSpec: MacAlgSpec<AlgorithmIdentifier>): MacCalculator<AlgorithmIdentifier>
    {
        return BaseHMacCalculator(secretKey, findPrfAlgId(prfType))
    }

    override fun macVerifier(macAlgSpec: MacAlgSpec<AlgorithmIdentifier>): MacVerifier<AlgorithmIdentifier>
    {
        return BaseHMacVerifier(secretKey, findPrfAlgId(prfType))
    }
}

/**
 * Operational interface for a symmetric key associated with MAC generation and verification.
 */
interface AuthenticationKey
{
    /**
     * Size of the key in bits.
     */
    val size: Int

    /**
     * Create a MAC calculator base on this key.
     *
     * @param macAlgSpec the algorithm specification for describing the calculator's MAC algorithm.
     * @return a calculator that produces MACs of specified type.
     */
    fun macCalculator(macAlgSpec: MacAlgSpec<AlgorithmIdentifier>): MacCalculator<AlgorithmIdentifier>

    /**
     * Create a MAC verifier base on this key.
     *
     * @param macAlgSpec the algorithm specification for describing the verifier's MAC algorithm.
     * @return a verifier that verifies MACs of specified type.
     */
    fun macVerifier(macAlgSpec: MacAlgSpec<AlgorithmIdentifier>): MacVerifier<AlgorithmIdentifier>
}