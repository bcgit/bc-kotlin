import org.bouncycastle.kcrypto.Digest
import org.bouncycastle.util.Arrays
import org.bouncycastle.util.Strings
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.security.MessageDigest
import kotlin.experimental.xor

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DigestTest {

    init {
        initProvider()
    }


    val digests = arrayOf(Digest.SHA1, Digest.SHA224, Digest.SHA256, Digest.SHA384, Digest.SHA512)

    @Test
    fun `round trip digests`() {

        val msg = Strings.toByteArray("Hello World!")
        for (digest in digests) {
            val calculator = digest.digestCalculator().apply {
                use {
                    it.stream.write(msg)
                }
            }

            val verifier = digest.digestVerifier().apply {
                this.stream.use { it.write(msg) }
            }
            val expected = calculator.digest()
            assertTrue(verifier.verify(expected))

            val jcaDig = MessageDigest.getInstance(digest.algorithmName)

            assertTrue(Arrays.areEqual(expected, jcaDig.digest(msg)))
        }

    }


    @Test
    fun `vandalise digests`() {

        val msg = Strings.toByteArray("Hello World!")
        for (digest in digests) {
            val calculator = digest.digestCalculator().apply {
                use {
                    it.stream.write(msg)
                }
            }

            val vandalisedDigest = calculator.digest()

            vandalisedDigest[0] = vandalisedDigest[0] xor 1

            val verifier = digest.digestVerifier().apply {

                this.stream.use { it.write(msg) }
            }
            assertFalse(verifier.verify(vandalisedDigest))
        }

    }

    @Test
    fun `wrong digests`() {

        val msg = Strings.toByteArray("Hello World!")
        var cnt = 1
        for (digest in digests) {
            val calculator = digest.digestCalculator().apply {
                use {
                    it.stream.write(msg)
                }
            }

            val verifierDigest = digests[cnt % digests.size]
            cnt++

            val verifier = verifierDigest.digestVerifier().apply {
                stream.use { it.write(msg) }
            }
            assertFalse(verifier.verify(calculator.digest()))
        }

    }


}