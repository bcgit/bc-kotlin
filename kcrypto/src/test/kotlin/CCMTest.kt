import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.cms.CCMParameters
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.spec.symmetric.AESGenSpec
import org.bouncycastle.kcrypto.spec.symmetric.CCMSpec
import org.bouncycastle.util.Arrays
//import org.hamcrest.MatcherAssert.assertThat
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.io.ByteArrayOutputStream
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.Security
import kotlin.experimental.xor

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class CCMTest {

    init {
        initProvider()
    }


    @Nested
    inner class `bounds testing`() {
        @Test
        fun `nonce length`() {


            //
            // One before start of nonce range.
            //
            val ex = if (KCryptoServices._provider!!.name == "BC")
                InvalidKeyException::class.java else InvalidAlgorithmParameterException::class.java

            assertThrows(ex, {
                val IV = ByteArray(6)
                KCryptoServices.symmetricKey(AESGenSpec(256)).apply {
                    ByteArrayOutputStream().apply {
                        encryptor(CCMSpec(IV, 128)).outputEncryptor(this)
                    }
                }

            }, "nonce must have length from 7 to 13 octets")


            //
            // One past end of nonce range.
            //
            assertThrows(ex, {
                val IV = ByteArray(14)
                KCryptoServices.symmetricKey(AESGenSpec(256)).apply {
                    ByteArrayOutputStream().apply {
                        encryptor(CCMSpec(IV, 128)).outputEncryptor(this)
                    }
                }

            }, "nonce must have length from 7 to 13 octets")


            //
            // At start of range.
            //
            var IV = ByteArray(7)
            KCryptoServices.symmetricKey(AESGenSpec(192)).apply {
                ByteArrayOutputStream().apply {
                    encryptor(CCMSpec(IV, 128)).outputEncryptor(this)
                }
            }


            //
            // At end of range..
            //
            IV = ByteArray(13)
            KCryptoServices.symmetricKey(AESGenSpec(128)).apply {
                ByteArrayOutputStream().apply {
                    encryptor(CCMSpec(IV, 128)).outputEncryptor(this)
                }
            }


        }


        @Test
        fun `wrong oid`() {
            assertThrows(IllegalStateException::class.java, {
                val IV = ByteArray(10)
                KCryptoServices.symmetricKey(AESGenSpec(256)).apply {
                    val ai = AlgorithmIdentifier(NISTObjectIdentifiers.id_aes128_CCM, CCMParameters(IV, (128 + 7) / 8))
                    val spec = CCMSpec(ai).validatedSpec(this)
                    ByteArrayOutputStream().apply {
                        encryptor(spec).outputEncryptor(this)
                    }
                }

            }, "key not matched to CCMSpec")




            assertThrows(IllegalStateException::class.java, {
                val IV = ByteArray(10)
                KCryptoServices.symmetricKey(AESGenSpec(192)).apply {

                    // nb GCM not CCM
                    val ai = AlgorithmIdentifier(NISTObjectIdentifiers.id_aes128_GCM, CCMParameters(IV, (128 + 7) / 8))
                    val spec = CCMSpec(ai).validatedSpec(this)
                    ByteArrayOutputStream().apply {
                        encryptor(spec).outputEncryptor(this)
                    }
                }

            }, "key not matched to CCMSpec")


        }


    }


    @Test
    fun `test alg id reconstitution`() {
        val IV = ByteArray(10)
        val aad = "There is a green door.".toByteArray() // Defaults to UTF8 in Kotlin
        val message = "0123456789".toByteArray()

        KCryptoServices.secureRandom.nextBytes(IV)



        KCryptoServices.symmetricKey(AESGenSpec(128)).apply {


            val encSpec = CCMSpec(IV, 16).validatedSpec(this)

            val cipherTextStream = ByteArrayOutputStream().apply {
                encryptor(encSpec).outputEncryptor(this).apply {
                    aadStream.write(aad)
                    encStream.use {
                        it.write(message)
                    }
                }
            }

            //
            // Rebuild spec.
            //
            val decSpec = CCMSpec(encSpec.algorithmIdentifier.parameters.toASN1Primitive().getEncoded()).validatedSpec(this)

            val plainTextStream = ByteArrayOutputStream().apply {
                decryptor(decSpec).outputDecryptor(this).apply {
                    aadStream.write(aad)
                    decStream.use {
                        it.write(cipherTextStream.toByteArray())
                    }

                }
            }


            assertTrue(Arrays.areEqual(message, plainTextStream.toByteArray()))
        }

    }

    @Test
    fun `tag length varies`() {
        val IV = ByteArray(10)
        val aad = "There is a green door.".toByteArray() // Defaults to UTF8 in Kotlin
        val message = "0123456789".toByteArray()

        KCryptoServices.secureRandom.nextBytes(IV)


        val cipherText = fun(tagSize: Int): Int {
            KCryptoServices.symmetricKey(AESGenSpec(128)).apply {
                val cipherTextStream = ByteArrayOutputStream().apply {
                    encryptor(CCMSpec(IV, tagSize)).outputEncryptor(this).apply {
                        aadStream.write(aad)
                        encStream.use {
                            it.write(message)
                        }
                    }
                }

                return cipherTextStream.size()
            }
        }

        //
        // detect the existing behavior does not suddenly change.
        //
//            assertThat("tag len of 1 is cipher text of 11", cipherText(1) == 11)
//            assertThat("tag len of 0 is cipher text of 10", cipherText(0) == 10)
//            assertThat("tag len of -1 is cipher text of 10", cipherText(-1) == 10)

    }


    @Nested
    inner class `AES 128 CCM`() : tests(128, NISTObjectIdentifiers.id_aes128_CCM)

    @Nested
    inner class `AES 192 CCM`() : tests(192, NISTObjectIdentifiers.id_aes192_CCM)

    @Nested
    inner class `AES 256 CCM`() : tests(256, NISTObjectIdentifiers.id_aes256_CCM)


    inner abstract class tests(val keySize: Int, val oid: ASN1ObjectIdentifier) {

        @Test
        fun `round trip`() {

            val IV = ByteArray(10)
            val aad = "There is a green door.".toByteArray() // Defaults to UTF8 in Kotlin
            val message = "0123456789".toByteArray()

            KCryptoServices.secureRandom.nextBytes(IV)



            KCryptoServices.symmetricKey(AESGenSpec(keySize)).apply {

                //
                // "this" is the key!
                // eg this.encryptor etc.
                //

                val cipherTextStream = ByteArrayOutputStream().apply {
                    encryptor(CCMSpec(IV, 16)).outputEncryptor(this).apply {
                        aadStream.write(aad)
                        encStream.use {
                            it.write(message)
                        }
                    }
                }


                val plainTextStream = ByteArrayOutputStream().apply {
                    decryptor(CCMSpec(IV, 16)).outputDecryptor(this).apply {
                        aadStream.write(aad)
                        decStream.use {
                            it.write(cipherTextStream.toByteArray())
                        }

                    }
                }


                assertTrue(Arrays.areEqual(message, plainTextStream.toByteArray()))
            }


        }


        @Test
        fun `basic tampering with message start`() {

            val IV = ByteArray(10)
            val aad = "There is a green door.".toByteArray() // Defaults to UTF8 in Kotlin
            val message = "The password for tuesday is ...".toByteArray()

            KCryptoServices.secureRandom.nextBytes(IV)



            KCryptoServices.symmetricKey(AESGenSpec(keySize)).apply {

                //
                // "this" is the key!
                // eg this.encryptor etc.
                //


                var cipherTextStream = ByteArrayOutputStream()
                cipherTextStream.use {
                    encryptor(CCMSpec(IV, 16)).outputEncryptor(it).apply {
                        aadStream.write(aad)
                        encStream.use {
                            it.write(message)
                        }
                    }
                }


                //
                // Damage message part.
                //
                var ct = cipherTextStream.toByteArray().clone()
                ct[0] = ct[0] xor 1

                try {
                    ByteArrayOutputStream().apply {
                        decryptor(CCMSpec(IV, 16)).outputDecryptor(this).apply {
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
                        "mac check in CCM failed"
                    } else {
                        "Error finalising cipher data: mac check in CCM failed"
                    }

                    assertTrue(ex.cause?.message.equals(expect))
                }

            }

        }


        @Test
        fun `basic tampering with message end`() {

            val IV = ByteArray(10)
            val aad = "There is a green door.".toByteArray() // Defaults to UTF8 in Kotlin
            val message = "The password for tuesday is ...".toByteArray()

            KCryptoServices.secureRandom.nextBytes(IV)



            KCryptoServices.symmetricKey(AESGenSpec(keySize)).apply {

                //
                // "this" is the key!
                // eg this.encryptor etc.
                //


                var cipherTextStream = ByteArrayOutputStream()
                cipherTextStream.use {
                    encryptor(CCMSpec(IV, 16)).outputEncryptor(it).apply {
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
                        decryptor(CCMSpec(IV, 16)).outputDecryptor(this).apply {
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
                        "mac check in CCM failed"
                    } else {
                        "Error finalising cipher data: mac check in CCM failed"
                    }

                    assertTrue(ex.cause?.message.equals(expect))
                }


            }


        }

        @Test
        fun `basic tampering with the associated data`() {

            val IV = ByteArray(10)
            val aad = "There is a green door.".toByteArray() // Defaults to UTF8 in Kotlin
            val message = "The password for tuesday is ...".toByteArray()

            KCryptoServices.secureRandom.nextBytes(IV)


            KCryptoServices.symmetricKey(AESGenSpec(keySize)).apply {

                //
                // "this" is the key!
                // eg this.encryptor etc.
                //


                var cipherTextStream = ByteArrayOutputStream()
                cipherTextStream.use {
                    encryptor(CCMSpec(IV, 16)).outputEncryptor(it).apply {
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
                        decryptor(CCMSpec(IV, 16)).outputDecryptor(this).apply {
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
                        "mac check in CCM failed"
                    } else {
                        "Error finalising cipher data: mac check in CCM failed"
                    }

                    assertTrue(ex.cause?.message.equals(expect))
                }


            }
        }

    }


}

