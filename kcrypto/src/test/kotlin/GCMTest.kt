import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.spec.symmetric.AESGenSpec
import org.bouncycastle.kcrypto.spec.symmetric.GCMSpec
import org.bouncycastle.util.Arrays
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.io.ByteArrayOutputStream
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.xor

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class GCMTest {

    init {
        initProvider()
    }


    @Test
    fun `spec rebuilding`() {

        val IV = ByteArray(128)
        val aad = "There is a green door.".toByteArray() // Defaults to UTF8 in Kotlin
        val message = "The password for tuesday is ...".toByteArray()

        KCryptoServices.secureRandom.nextBytes(IV)

        KCryptoServices.symmetricKey(AESGenSpec(128)).apply {

            //
            // "this" is the key!
            // eg this.outputencryptor etc.
            //

            val encSpec = GCMSpec(IV, 128).validatedSpec(this)

            val cipherTextStream = ByteArrayOutputStream().apply {
                encryptor(encSpec).outputEncryptor(this).use {
                    it.aadStream.write(aad)
                    it.encStream.write(message)
                }
            }

            val decSpec = GCMSpec(AlgorithmIdentifier.getInstance(encSpec.algorithmIdentifier.getEncoded()))

            val plainTextStream = ByteArrayOutputStream().apply {
                decryptor(decSpec).outputDecryptor(this).use {
                    it.aadStream.write(aad)
                    it.decStream.write(cipherTextStream.toByteArray())
                }
            }

            assertTrue(Arrays.areEqual(message, plainTextStream.toByteArray()))
        }
    }


    @Test
    fun `basic roundtrip`() {

        val IV = ByteArray(128)
        val aad = "There is a green door.".toByteArray() // Defaults to UTF8 in Kotlin
        val message = "The password for tuesday is ...".toByteArray()

        KCryptoServices.secureRandom.nextBytes(IV)

        KCryptoServices.symmetricKey(AESGenSpec(128)).apply {

            //
            // "this" is the key!
            // eg this.outputencryptor etc.
            //

            val cipherTextStream = ByteArrayOutputStream().apply {
                encryptor(GCMSpec(IV, 128)).outputEncryptor(this).use {
                    it.aadStream.write(aad)
                    it.encStream.write(message)
                }
            }

            val plainTextStream = ByteArrayOutputStream().apply {
                decryptor(GCMSpec(IV, 128)).outputDecryptor(this).use {
                    it.aadStream.write(aad)
                    it.decStream.write(cipherTextStream.toByteArray())
                }
            }

            assertTrue(Arrays.areEqual(message, plainTextStream.toByteArray()))

            val c = Cipher.getInstance("GCM", KCryptoServices._provider)

            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(this.encoding, "AES"), GCMParameterSpec(128, IV))

            c.updateAAD(aad)

            assertTrue(Arrays.areEqual(message, c.doFinal(cipherTextStream.toByteArray())))
        }
    }


    @Test
    fun `basic tampering with message start`() {

        val IV = ByteArray(128)
        val aad = "There is a green door.".toByteArray() // Defaults to UTF8 in Kotlin
        val message = "The password for tuesday is ...".toByteArray()

        KCryptoServices.secureRandom.nextBytes(IV)

        KCryptoServices.symmetricKey(AESGenSpec(128)).apply {

            //
            // "this" is the key!
            // eg this.outputencryptor etc.
            //


            var cipherTextStream = ByteArrayOutputStream()
            cipherTextStream.use {
                encryptor(GCMSpec(IV, 128)).outputEncryptor(it).use {
                    it.aadStream.write(aad)
                    it.encStream.write(message)
                }
            }


            //
            // Damage message part.
            //
            var ct = cipherTextStream.toByteArray().clone()
            ct[0] = ct[0] xor 1

            try {
                ByteArrayOutputStream().apply {
                    decryptor(GCMSpec(IV, 128)).outputDecryptor(this).use {
                        it.aadStream.write(aad)
                        it.decStream.write(ct)
                    }
                }
                fail<Unit>("Must fail, damaged message")
            } catch (ex: Exception) {
                assertNotNull(ex.cause)

                val expect = if (KCryptoServices._provider!!.name.equals("BC")) {
                    "mac check in GCM failed"
                } else {
                    "Error finalising cipher data: mac check in GCM failed"
                }

                assertTrue(ex.cause?.message.equals(expect))
            }

        }

    }


    @Test
    fun `basic tampering with message end`() {

        val IV = ByteArray(128)
        val aad = "There is a green door.".toByteArray() // Defaults to UTF8 in Kotlin
        val message = "The password for tuesday is ...".toByteArray()

        KCryptoServices.secureRandom.nextBytes(IV)



        KCryptoServices.symmetricKey(AESGenSpec(128)).apply {

            //
            // "this" is the key!
            // eg this.outputencryptor etc.
            //


            var cipherTextStream = ByteArrayOutputStream()
            cipherTextStream.use {
                encryptor(GCMSpec(IV, 128)).outputEncryptor(it).apply {
                    aadStream.write(aad)
                    encStream.use {
                        it.write(message)
                    }
                }
            }


            //
            // Damage tag part.
            //

            val ct = cipherTextStream.toByteArray().clone()
            ct[ct.size - 1] = ct[ct.size - 1] xor 1
            try {
                ByteArrayOutputStream().apply {
                    decryptor(GCMSpec(IV, 128)).outputDecryptor(this).apply {
                        aadStream.write(aad)
                        decStream.use {
                            it.write(ct)
                        }
                    }
                }
                fail<Unit>("Must fail, damaged message")
            } catch (ex: Exception) {
                assertNotNull(ex.cause)
                val expect = if (KCryptoServices._provider!!.name.equals("BC")) {
                    "mac check in GCM failed"
                } else {
                    "Error finalising cipher data: mac check in GCM failed"
                }

                assertTrue(ex.cause?.message.equals(expect))
            }


        }


    }

    @Test
    fun `basic tampering with the associated data`() {

        val IV = ByteArray(128)
        val aad = "There is a green door.".toByteArray() // Defaults to UTF8 in Kotlin
        val message = "The password for tuesday is ...".toByteArray()

        KCryptoServices.secureRandom.nextBytes(IV)



        KCryptoServices.symmetricKey(AESGenSpec(128)).apply {

            //
            // "this" is the key!
            // eg this.outputencryptor etc.
            //


            var cipherTextStream = ByteArrayOutputStream()
            cipherTextStream.use {
                encryptor(GCMSpec(IV, 128)).outputEncryptor(it).apply {
                    aadStream.write(aad)
                    encStream.use {
                        it.write(message)
                    }
                }
            }


            //
            // Damage associated data.
            //
            val brokenAAD = aad.clone()
            brokenAAD[0] = brokenAAD[0] xor 1
            try {
                ByteArrayOutputStream().apply {
                    decryptor(GCMSpec(IV, 128)).outputDecryptor(this).apply {
                        aadStream.write(brokenAAD)
                        decStream.use {
                            it.write(cipherTextStream.toByteArray())
                        }
                    }
                }
                fail<Unit>("Must fail, aad damaged")
            } catch (ex: Exception) {
                assertNotNull(ex.cause)
                val expect = if (KCryptoServices._provider!!.name.equals("BC")) {
                    "mac check in GCM failed"
                } else {
                    "Error finalising cipher data: mac check in GCM failed"
                }

                assertTrue(ex.cause?.message.equals(expect))
            }


        }


    }
}