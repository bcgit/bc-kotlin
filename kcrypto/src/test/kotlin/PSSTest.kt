import org.bouncycastle.kcrypto.Digest
import org.bouncycastle.kcrypto.spec.asymmetric.PSSSigSpec
import org.bouncycastle.kcrypto.spec.asymmetric.RSAGenSpec
import org.bouncycastle.util.Strings
import org.bouncycastle.util.encoders.Base64
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import kotlin.experimental.xor

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PSSTest {

    private val privKeySpec = PKCS8EncodedKeySpec(Base64.decode(
            "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"))

    private val pubKeySpec = X509EncodedKeySpec(Base64.decode(
                    "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAzyrpV7Ej7Df8Bt6hP46CbhZM3C2U3eIhkhnFatyaiaheWk1iPV60ggxj7r5B/NA7yaeZ7Tyoj1ur9XNeZ85JjbRK4KEzGvz28nzGKoK9L0pdxL/zDjXlcslgwOvmUAeWC5sumFhT3Vwxe+1B3A2Hgv3nZ1u/8rAQP5gUQzfQstzY4NykMltMWG5miV/AYiQ5W0qs2EeaDOm8E1sYGQl5LHcvYzt5e5ubu767Yj+w4ptW/GbCnjetya9ZUC6pyt1AZfOUHWFbuy7Z7/1ueMC7wfi11mDy+EERV4z28Ut66bd9rhphudkEnC/PwIBH7i9aJJsEoXlddIV2mGyoNuIp0mXSj14C3+yAbmU8GMEXikhOia3XJlJay8v+i/O5d5UNg8P96AH/SWU+M54GAwyCXPtoTDaSSoLq1JKQaeLPhQ/5x9c/vrQFsXEC7ai9/4RQk61/vwp7+WK+kliNupnW3O2XaGkSQHXTNs0L8F1fwiWXR7a2OoJXWHRqT6GAi/9eIXYOVSoSvT/dPfqLwQ1Df/XpqiH0aP1MSCq1oVqShsgnR4BuwEx/wpnDyM6A0SstZIdZt77mLo04E1nTvhuk41VueMgba4tPJFC1DUxkKs5X/C9kgqI1GZP6kGrR02EoPtTayBzHOUzDkIDstt4qnKfiIC58p5ohJdqovuuyv5ECAwEAAQ=="))

    val privKey: PrivateKey
    val pubKey: PublicKey

    init {
        initProvider()
        val fact = KeyFactory.getInstance("RSA", KCryptoServices._provider)
        privKey = fact.generatePrivate(privKeySpec)
        pubKey = fact.generatePublic(pubKeySpec)
    }

    val input = byteArrayOf(0x54.toByte(), 0x85.toByte(), 0x9b.toByte(), 0x34.toByte(), 0x2c.toByte(), 0x49.toByte(), 0xea.toByte(), 0x2a.toByte())


    @Test
    fun `pss sha1`() {

        val msg = Strings.toByteArray("Hello World!")

        val sigCalc = KCryptoServices
                .signingKey(privKey.encoded, RSAGenSpec.signType)
                .signatureCalculator(PSSSigSpec(Digest.SHA1))

        sigCalc.use {
            it.stream.write(msg)
        }

        val sig = sigCalc.signature()


        val sigVer = KCryptoServices
                .verificationKey(pubKey.encoded, RSAGenSpec.verifyType)
                .signatureVerifier(PSSSigSpec(Digest.SHA1))

        sigVer.use {
            it.stream.write(msg)
        }

        assertTrue(sigVer.verifies(sig))

        val s = Signature.getInstance("SHA1withRSAandMGF1", KCryptoServices._provider)

        s.initVerify(pubKey)

        s.update(msg)

        assertTrue(s.verify(sig))

        sig[0] = sig[0] xor 1

        try {
            val sigVer2 = KCryptoServices
                    .verificationKey(pubKey.encoded, RSAGenSpec.verifyType)
                    .signatureVerifier(PSSSigSpec(Digest.SHA1))

            sigVer2.use {
                it.stream.write(msg)
            }

            assertFalse(sigVer2.verifies(sig), "Must fail")
        } catch (ex: Exception) {
            // OK
        }
    }


    @Test
    fun `pss sha224`() {

        val msg = Strings.toByteArray("Hello World!")

        val sigCalc = KCryptoServices
                .signingKey(privKey.encoded, RSAGenSpec.signType)
                .signatureCalculator(PSSSigSpec(Digest.SHA224))

        sigCalc.use {
            it.stream.write(msg)
        }

        val sig = sigCalc.signature()


        val sigVer = KCryptoServices
                .verificationKey(pubKey.encoded, RSAGenSpec.verifyType)
                .signatureVerifier(PSSSigSpec(Digest.SHA224))

        sigVer.use {
            it.stream.write(msg)
        }

        assertTrue(sigVer.verifies(sig))

        val s = Signature.getInstance("SHA224withRSAandMGF1", KCryptoServices._provider)

        s.initVerify(pubKey)

        s.update(msg)

        assertTrue(s.verify(sig))

        sig[0] = sig[0] xor 1

        try {
            val sigVer2 = KCryptoServices
                    .verificationKey(pubKey.encoded, RSAGenSpec.verifyType)
                    .signatureVerifier(PSSSigSpec(Digest.SHA224))

            sigVer2.use {
                it.stream.write(msg)
            }

            assertFalse(sigVer2.verifies(sig), "Must fail")
        } catch (ex: Exception) {
            // OK
        }

    }

    @Test
    fun `pss sha256`() {
        val msg = Strings.toByteArray("Hello World!")

        val sigCalc = KCryptoServices
                .signingKey(privKey.encoded, RSAGenSpec.signType)
                .signatureCalculator(PSSSigSpec(Digest.SHA256))

        sigCalc.use {
            it.stream.write(msg)
        }

        val sig = sigCalc.signature()


        val sigVer = KCryptoServices
                .verificationKey(pubKey.encoded, RSAGenSpec.verifyType)
                .signatureVerifier(PSSSigSpec(Digest.SHA256))

        sigVer.use {
            it.stream.write(msg)
        }

        assertTrue(sigVer.verifies(sig))

        val s = Signature.getInstance("SHA256withRSAandMGF1", KCryptoServices._provider)

        s.initVerify(pubKey)

        s.update(msg)

        assertTrue(s.verify(sig))

        sig[0] = sig[0] xor 1

        try {
            val sigVer2 = KCryptoServices
                    .verificationKey(pubKey.encoded, RSAGenSpec.verifyType)
                    .signatureVerifier(PSSSigSpec(Digest.SHA256))

            sigVer2.use {
                it.stream.write(msg)
            }

            assertFalse(sigVer2.verifies(sig), "Must fail")
        } catch (ex: Exception) {
            // OK
        }
    }

    @Test
    fun `pss sha384`() {

        val msg = Strings.toByteArray("Hello World!")

        val sigCalc = KCryptoServices
                .signingKey(privKey.encoded, RSAGenSpec.signType)
                .signatureCalculator(PSSSigSpec(Digest.SHA384))

        sigCalc.use {
            it.stream.write(msg)
        }

        val sig = sigCalc.signature()


        val sigVer = KCryptoServices
                .verificationKey(pubKey.encoded, RSAGenSpec.verifyType)
                .signatureVerifier(PSSSigSpec(Digest.SHA384))

        sigVer.use {
            it.stream.write(msg)
        }

        assertTrue(sigVer.verifies(sig))

        val s = Signature.getInstance("SHA384withRSAandMGF1", KCryptoServices._provider)

        s.initVerify(pubKey)

        s.update(msg)

        assertTrue(s.verify(sig))

        sig[0] = sig[0] xor 1

        try {
            val sigVer2 = KCryptoServices
                    .verificationKey(pubKey.encoded, RSAGenSpec.verifyType)
                    .signatureVerifier(PSSSigSpec(Digest.SHA384))

            sigVer2.use {
                it.stream.write(msg)
            }

            assertFalse(sigVer.verifies(sig), "Must fail")
        } catch (ex: Exception) {
            // OK
        }

    }

    @Test
    fun `pss sha512`() {

        val msg = Strings.toByteArray("Hello World!")

        val sigCalc = KCryptoServices
                .signingKey(privKey.encoded, RSAGenSpec.signType)
                .signatureCalculator(PSSSigSpec(Digest.SHA512))

        sigCalc.use {
            it.stream.write(msg)
        }

        val sig = sigCalc.signature()


        val sigVer = KCryptoServices
                .verificationKey(pubKey.encoded, RSAGenSpec.verifyType)
                .signatureVerifier(PSSSigSpec(Digest.SHA512))

        sigVer.use {
            it.stream.write(msg)
        }

        assertTrue(sigVer.verifies(sig))

        val s = Signature.getInstance("SHA512withRSAandMGF1", KCryptoServices._provider)

        s.initVerify(pubKey)

        s.update(msg)

        assertTrue(s.verify(sig))

        sig[0] = sig[0] xor 1

        try {
            val sigVer2 = KCryptoServices
                    .verificationKey(pubKey.encoded, RSAGenSpec.verifyType)
                    .signatureVerifier(PSSSigSpec(Digest.SHA512))

            sigVer2.use {
                it.stream.write(msg)
            }

            assertFalse(sigVer2.verifies(sig), "Must fail")
        } catch (ex: Exception) {
            // OK
        }
    }


}