import org.bouncycastle.kcrypto.Digest
import org.bouncycastle.kcrypto.dsl.*
import org.bouncycastle.kcrypto.spec.asymmetric.*
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
class LMSTest {

    init {
        initProvider()
    }

    val input = byteArrayOf(0x54.toByte(), 0x85.toByte(), 0x9b.toByte(), 0x34.toByte(), 0x2c.toByte(), 0x49.toByte(), 0xea.toByte(), 0x2a.toByte())


    @Test
    fun `lms sha256-n32-h10`() {

        val msg = Strings.toByteArray("Hello World!")

        var kp = signingKeyPair {
            lms {
                sigParameterSet = "lms-sha256-n32-h10"
                otsParameterSet = "sha256-n32-w2"
            }
        }

        val sigCalc = kp.signingKey.signatureCalculator(LMSSigSpec())

        sigCalc.use {
            it.stream.write(msg)
        }

        val sig = sigCalc.signature()
        val sigVer = kp.verificationKey.signatureVerifier(LMSSigSpec())

        sigVer.use {
            it.stream.write(msg)
        }

        assertTrue(sigVer.verifies(sig))

        val fact = KeyFactory.getInstance("LMS", "BCPQC")
        val pubKey = fact.generatePublic(X509EncodedKeySpec(kp.verificationKey.encoding))

        val s = Signature.getInstance("LMS", "BCPQC")

        s.initVerify(pubKey)

        s.update(msg)

        assertTrue(s.verify(sig))

        sig[0] = sig[0] xor 1

        try {
            val sigVer2 = KCryptoServices
                    .verificationKey(pubKey.encoded, LMSGenSpec.verifyType)
                    .signatureVerifier(FalconSigSpec())

            sigVer2.use {
                it.stream.write(msg)
            }

            assertFalse(sigVer2.verifies(sig), "Must fail")
        } catch (ex: Exception) {
            // OK
        }
    }
}