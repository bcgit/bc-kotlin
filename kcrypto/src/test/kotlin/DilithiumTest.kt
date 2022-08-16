import org.bouncycastle.kcrypto.dsl.dilithium
import org.bouncycastle.kcrypto.dsl.signingKeyPair
import org.bouncycastle.kcrypto.spec.asymmetric.DilithiumGenSpec
import org.bouncycastle.kcrypto.spec.asymmetric.DilithiumSigSpec
import org.bouncycastle.util.Strings
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import kotlin.experimental.xor

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DilithiumTest {

    init {
        initProvider()
        val fact = KeyFactory.getInstance("Dilithium", "BCPQC")
    }

    val input = byteArrayOf(
        0x54.toByte(),
        0x85.toByte(),
        0x9b.toByte(),
        0x34.toByte(),
        0x2c.toByte(),
        0x49.toByte(),
        0xea.toByte(),
        0x2a.toByte()
    )


    @Test
    fun `dilithium dilithium2`() {

        val msg = Strings.toByteArray("Hello World!")

        var kp = signingKeyPair {
            dilithium {
                parameterSet = "dilithium2"
            }
        }

        val sigCalc = kp.signingKey.signatureCalculator(DilithiumSigSpec())

        sigCalc.use {
            it.stream.write(msg)
        }

        val sig = sigCalc.signature()


        val sigVer = kp.verificationKey.signatureVerifier(DilithiumSigSpec())

        sigVer.use {
            it.stream.write(msg)
        }

        assertTrue(sigVer.verifies(sig))

        val fact = KeyFactory.getInstance("Dilithium", "BCPQC")
        val pubKey = fact.generatePublic(X509EncodedKeySpec(kp.verificationKey.encoding))

        val s = Signature.getInstance("Dilithium", "BCPQC")

        s.initVerify(pubKey)

        s.update(msg)

        assertTrue(s.verify(sig))

        sig[0] = sig[0] xor 1

        try {
            val sigVer2 = KCryptoServices
                .verificationKey(pubKey.encoded, DilithiumGenSpec.verifyType)
                .signatureVerifier(DilithiumSigSpec())

            sigVer2.use {
                it.stream.write(msg)
            }

            assertFalse(sigVer2.verifies(sig), "Must fail")
        } catch (ex: Exception) {
            // OK
        }
    }

    @Test
    fun `dilithium dilithium3`() {

        val msg = Strings.toByteArray("Hello World!")

        var kp = signingKeyPair {
            dilithium {
                parameterSet = "dilithium3"
            }
        }

        val sigCalc = kp.signingKey.signatureCalculator(DilithiumSigSpec())

        sigCalc.use {
            it.stream.write(msg)
        }

        val sig = sigCalc.signature()


        val sigVer = kp.verificationKey.signatureVerifier(DilithiumSigSpec())

        sigVer.use {
            it.stream.write(msg)
        }

        assertTrue(sigVer.verifies(sig))

        val fact = KeyFactory.getInstance("Dilithium", "BCPQC")
        val pubKey = fact.generatePublic(X509EncodedKeySpec(kp.verificationKey.encoding))

        val s = Signature.getInstance("Dilithium", "BCPQC")

        s.initVerify(pubKey)

        s.update(msg)

        assertTrue(s.verify(sig))

        sig[0] = sig[0] xor 1

        try {
            val sigVer2 = KCryptoServices
                .verificationKey(pubKey.encoded, DilithiumGenSpec.verifyType)
                .signatureVerifier(DilithiumSigSpec())

            sigVer2.use {
                it.stream.write(msg)
            }

            assertFalse(sigVer2.verifies(sig), "Must fail")
        } catch (ex: Exception) {
            // OK
        }

    }

    @Test
    fun `dilithium dilithium5`() {

        val msg = Strings.toByteArray("Hello World!")

        var kp = signingKeyPair {
            dilithium {
                parameterSet = "dilithium5"
            }
        }

        val sigCalc = kp.signingKey.signatureCalculator(DilithiumSigSpec())

        sigCalc.use {
            it.stream.write(msg)
        }

        val sig = sigCalc.signature()


        val sigVer = kp.verificationKey.signatureVerifier(DilithiumSigSpec())

        sigVer.use {
            it.stream.write(msg)
        }

        assertTrue(sigVer.verifies(sig))

        val fact = KeyFactory.getInstance("Dilithium", "BCPQC")
        val pubKey = fact.generatePublic(X509EncodedKeySpec(kp.verificationKey.encoding))

        val s = Signature.getInstance("Dilithium", "BCPQC")

        s.initVerify(pubKey)

        s.update(msg)

        assertTrue(s.verify(sig))

        sig[0] = sig[0] xor 1

        try {
            val sigVer2 = KCryptoServices
                .verificationKey(pubKey.encoded, DilithiumGenSpec.verifyType)
                .signatureVerifier(DilithiumSigSpec())

            sigVer2.use {
                it.stream.write(msg)
            }

            assertFalse(sigVer2.verifies(sig), "Must fail")
        } catch (ex: Exception) {
            // OK
        }

    }


}