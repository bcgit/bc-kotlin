import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.cms.CCMParameters
import org.bouncycastle.asn1.cms.GCMParameters
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.kcrypto.spec.symmetric.AESGenSpec
import org.bouncycastle.kcrypto.spec.symmetric.CCMSpec
import org.bouncycastle.kcrypto.spec.symmetric.GCMSpec

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.io.ByteArrayOutputStream
import java.security.InvalidAlgorithmParameterException
import java.security.Security

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SymAlgSpecTest {

    init {
        initProvider()
    }

    fun validateGCMSpec(keySize: Int, ivLen: Int, tagLen: Int, oid: ASN1ObjectIdentifier) {
        val IV = ByteArray(ivLen)
        val aad = ByteArray(10)
        val message = "test".toByteArray()

        KCryptoServices.secureRandom.nextBytes(IV)

        KCryptoServices.symmetricKey(AESGenSpec(keySize)).apply {
            val algID = AlgorithmIdentifier(oid, GCMParameters(IV, tagLen))

            val encSpec = GCMSpec(algID).validatedSpec(this)

            ByteArrayOutputStream().use {
                encryptor(encSpec).outputEncryptor(it).use {
                    it.aadStream.write(aad)
                    it.encStream.write(message)
                }
            }

        }
    }


    fun validateGCMSpecRaw(keySize: Int, ivLen: Int, tagLen: Int, oid: ASN1ObjectIdentifier) {
        val IV = ByteArray(ivLen)
        val aad = ByteArray(10)
        val message = "test".toByteArray()

        KCryptoServices.secureRandom.nextBytes(IV)

        KCryptoServices.symmetricKey(AESGenSpec(keySize)).apply {
            val encSpec = GCMSpec(IV, tagLen).validatedSpec(this)
            ByteArrayOutputStream().use {
                encryptor(encSpec).outputEncryptor(it).use {
                    it.aadStream.write(aad)
                    it.encStream.write(message)
                }
            }

        }
    }


    private class DefaultEx : Throwable() {

    }

    data class GCMVector(
        val keySize: Int,
        val ivLen: Int,
        val tagLen: Int,
        val oid: ASN1ObjectIdentifier,
        var ex: Class<out Throwable>? = null,
        val exMsg: String = "",
        val rawTag: Boolean = false
    )

    data class CCMVector(
        val keySize: Int,
        val nonceLen: Int,
        val icvLen: Int,
        val oid: ASN1ObjectIdentifier,
        var ex: Class<out Throwable>? = null,
        val exMsg: String = ""
    )

    @Nested
    inner class GCM {

        @Test
        fun `GCM spec validation`() {


            val vectors = arrayListOf(
                GCMVector(keySize = 128, ivLen = 32, tagLen = 12, oid = NISTObjectIdentifiers.id_aes128_GCM),
                GCMVector(keySize = 192, ivLen = 32, tagLen = 12, oid = NISTObjectIdentifiers.id_aes192_GCM),
                GCMVector(keySize = 256, ivLen = 32, tagLen = 12, oid = NISTObjectIdentifiers.id_aes256_GCM),

                // CCM oid.
                GCMVector(
                    keySize = 128,
                    ivLen = 32,
                    tagLen = 12,
                    oid = NISTObjectIdentifiers.id_aes128_CCM,
                    ex = IllegalStateException::class.java,
                    exMsg = "key not matched to GCMSpec"
                ),

                GCMVector(
                    keySize = 128,
                    ivLen = 32,
                    tagLen = 12,
                    oid = NISTObjectIdentifiers.id_aes256_GCM,
                    ex = IllegalStateException::class.java,
                    exMsg = "key not matched to GCMSpec"
                ),
                GCMVector(
                    keySize = 192,
                    ivLen = 32,
                    tagLen = 12,
                    oid = NISTObjectIdentifiers.id_aes128_GCM,
                    ex = IllegalStateException::class.java,
                    exMsg = "key not matched to GCMSpec"
                ),
                GCMVector(
                    keySize = 256,
                    ivLen = 32,
                    tagLen = 12,
                    oid = NISTObjectIdentifiers.id_aes192_GCM,
                    ex = IllegalStateException::class.java,
                    exMsg = "key not matched to GCMSpec"
                ),

                GCMVector(
                    keySize = 127,
                    ivLen = 32,
                    tagLen = 12,
                    oid = NISTObjectIdentifiers.id_aes128_GCM,
                    ex = IllegalArgumentException::class.java,
                    exMsg = "keySize must be one of (128, 192, 256)"
                ),
                GCMVector(
                    keySize = 193,
                    ivLen = 32,
                    tagLen = 12,
                    oid = NISTObjectIdentifiers.id_aes192_GCM,
                    ex = IllegalArgumentException::class.java,
                    exMsg = "keySize must be one of (128, 192, 256)"
                ),
                GCMVector(
                    keySize = 255,
                    ivLen = 32,
                    tagLen = 12,
                    oid = NISTObjectIdentifiers.id_aes256_GCM,
                    ex = IllegalArgumentException::class.java,
                    exMsg = "keySize must be one of (128, 192, 256)"
                ),

                GCMVector(
                    keySize = 128,
                    ivLen = 32,
                    tagLen = 10,
                    oid = NISTObjectIdentifiers.id_aes128_GCM,
                    ex = InvalidAlgorithmParameterException::class.java,
                    exMsg = "Invalid value for MAC size: 16",
                    rawTag = true
                )
                ,
                GCMVector(
                    keySize = 192,
                    ivLen = 32,
                    tagLen = 10,
                    oid = NISTObjectIdentifiers.id_aes192_GCM,
                    ex = InvalidAlgorithmParameterException::class.java,
                    exMsg = "Invalid value for MAC size: 16",
                    rawTag = true
                ),
                GCMVector(
                    keySize = 256,
                    ivLen = 32,
                    tagLen = 10,
                    oid = NISTObjectIdentifiers.id_aes256_GCM,
                    ex = InvalidAlgorithmParameterException::class.java,
                    exMsg = "Invalid value for MAC size: 16",
                    rawTag = true
                ),

                GCMVector(
                    keySize = 128,
                    ivLen = 32,
                    tagLen = 17,
                    oid = NISTObjectIdentifiers.id_aes128_GCM,
                    ex = InvalidAlgorithmParameterException::class.java,
                    exMsg = "Invalid value for MAC size: 24",
                    rawTag = true
                ),
                GCMVector(
                    keySize = 192,
                    ivLen = 32,
                    tagLen = 17,
                    oid = NISTObjectIdentifiers.id_aes192_GCM,
                    ex = InvalidAlgorithmParameterException::class.java,
                    exMsg = "Invalid value for MAC size: 24",
                    rawTag = true
                ),
                GCMVector(
                    keySize = 256,
                    ivLen = 32,
                    tagLen = 17,
                    oid = NISTObjectIdentifiers.id_aes256_GCM,
                    ex = InvalidAlgorithmParameterException::class.java,
                    exMsg = "Invalid value for MAC size: 24",
                    rawTag = true
                )


            )

            for (vector in vectors) {
                if (vector.ex == null) {
                    validateGCMSpec(vector.keySize, vector.ivLen, vector.tagLen, vector.oid)
                } else {
                    if (vector.rawTag) {
                        val ex = assertThrows(vector.ex) {
                            validateGCMSpecRaw(vector.keySize, vector.ivLen, vector.tagLen, vector.oid)
                        }
                        assertEquals(vector.exMsg, ex.message)
                    } else {
                        val ex = assertThrows(vector.ex) {
                            validateGCMSpec(vector.keySize, vector.ivLen, vector.tagLen, vector.oid)
                        }
                        assertEquals(vector.exMsg, ex.message)
                    }
                }

            }
        }


        @Test
        fun `test with tagSize`() {
            val IV = ByteArray(16)
            val aad = ByteArray(10)
            val message = "test".toByteArray()

            KCryptoServices.secureRandom.nextBytes(IV)

            KCryptoServices.symmetricKey(AESGenSpec(128)).apply {
                val algID = AlgorithmIdentifier(NISTObjectIdentifiers.id_aes128_GCM, GCMParameters(IV, 16))
                val toTestSpec = GCMSpec(IV, 128).validatedSpec(this)
                assertArrayEquals(algID.getEncoded(), toTestSpec.algorithmIdentifier.getEncoded())
            }

            KCryptoServices.symmetricKey(AESGenSpec(192)).apply {
                val algID = AlgorithmIdentifier(NISTObjectIdentifiers.id_aes192_GCM, GCMParameters(IV, 16))
                val toTestSpec = GCMSpec(IV, 128).validatedSpec(this)
                assertArrayEquals(algID.getEncoded(), toTestSpec.algorithmIdentifier.getEncoded())
            }


            KCryptoServices.symmetricKey(AESGenSpec(256)).apply {
                val algID = AlgorithmIdentifier(NISTObjectIdentifiers.id_aes256_GCM, GCMParameters(IV, 16))
                val toTestSpec = GCMSpec(IV, 128).validatedSpec(this)
                assertArrayEquals(algID.getEncoded(), toTestSpec.algorithmIdentifier.getEncoded())
            }

        }


    }

    @Nested
    inner class CCM {


        fun validateCCMSpec(keySize: Int, ivLen: Int, icvLen: Int, oid: ASN1ObjectIdentifier) {
            val nonce = ByteArray(ivLen)
            val aad = ByteArray(10)
            val message = "test".toByteArray()

            KCryptoServices.secureRandom.nextBytes(nonce)

            KCryptoServices.symmetricKey(AESGenSpec(keySize)).apply {
                val algID = AlgorithmIdentifier(oid, CCMParameters(nonce, icvLen))
                val encSpec = CCMSpec(algID).validatedSpec(this)

                ByteArrayOutputStream().use {
                    encryptor(encSpec).outputEncryptor(it).use {
                        it.aadStream.write(aad)
                        it.encStream.write(message)
                    }
                }

            }
        }

        @Test
        fun `CCM spec validation`() {
            val vectors = arrayListOf(
                CCMVector(keySize = 128, nonceLen = 13, icvLen = 12, oid = NISTObjectIdentifiers.id_aes128_CCM),
                CCMVector(keySize = 192, nonceLen = 13, icvLen = 12, oid = NISTObjectIdentifiers.id_aes192_CCM),
                CCMVector(keySize = 256, nonceLen = 13, icvLen = 12, oid = NISTObjectIdentifiers.id_aes256_CCM),

                // GCM oid.
                CCMVector(
                    keySize = 128,
                    nonceLen = 13,
                    icvLen = 12,
                    oid = NISTObjectIdentifiers.id_aes128_GCM,
                    ex = IllegalStateException::class.java,
                    exMsg = "key not matched to CCMSpec"
                ),

                CCMVector(
                    keySize = 128,
                    nonceLen = 13,
                    icvLen = 12,
                    oid = NISTObjectIdentifiers.id_aes256_CCM,
                    ex = IllegalStateException::class.java,
                    exMsg = "key not matched to CCMSpec"
                ),
                CCMVector(
                    keySize = 192,
                    nonceLen = 13,
                    icvLen = 12,
                    oid = NISTObjectIdentifiers.id_aes128_CCM,
                    ex = IllegalStateException::class.java,
                    exMsg = "key not matched to CCMSpec"
                ),
                CCMVector(
                    keySize = 256,
                    nonceLen = 13,
                    icvLen = 12,
                    oid = NISTObjectIdentifiers.id_aes192_CCM,
                    ex = IllegalStateException::class.java,
                    exMsg = "key not matched to CCMSpec"
                ),

                CCMVector(
                    keySize = 127,
                    nonceLen = 12,
                    icvLen = 12,
                    oid = NISTObjectIdentifiers.id_aes128_CCM,
                    ex = IllegalArgumentException::class.java,
                    exMsg = "keySize must be one of (128, 192, 256)"
                ),
                CCMVector(
                    keySize = 193,
                    nonceLen = 12,
                    icvLen = 12,
                    oid = NISTObjectIdentifiers.id_aes192_CCM,
                    ex = IllegalArgumentException::class.java,
                    exMsg = "keySize must be one of (128, 192, 256)"
                ),
                CCMVector(
                    keySize = 255,
                    nonceLen = 12,
                    icvLen = 12,
                    oid = NISTObjectIdentifiers.id_aes256_CCM,
                    ex = IllegalArgumentException::class.java,
                    exMsg = "keySize must be one of (128, 192, 256)"
                ),

                CCMVector(
                    keySize = 128,
                    nonceLen = 17,
                    icvLen = 10,
                    oid = NISTObjectIdentifiers.id_aes128_CCM,
                    ex = InvalidAlgorithmParameterException::class.java,
                    exMsg = "nonce must have length from 7 to 13 octets"
                ),
                CCMVector(
                    keySize = 192,
                    nonceLen = 17,
                    icvLen = 10,
                    oid = NISTObjectIdentifiers.id_aes192_CCM,
                    ex = InvalidAlgorithmParameterException::class.java,
                    exMsg = "nonce must have length from 7 to 13 octets"
                ),
                CCMVector(
                    keySize = 256,
                    nonceLen = 17,
                    icvLen = 10,
                    oid = NISTObjectIdentifiers.id_aes256_CCM,
                    ex = InvalidAlgorithmParameterException::class.java,
                    exMsg = "nonce must have length from 7 to 13 octets"
                ),

                CCMVector(
                    keySize = 128,
                    nonceLen = 13,
                    icvLen = 17,
                    oid = NISTObjectIdentifiers.id_aes128_CCM,
                    ex = InvalidCipherTextException::class.java,
                    exMsg = "Error during cipher finalisation"
                ),
                CCMVector(
                    keySize = 192,
                    nonceLen = 13,
                    icvLen = 17,
                    oid = NISTObjectIdentifiers.id_aes192_CCM,
                    ex = InvalidCipherTextException::class.java,
                    exMsg = "Error during cipher finalisation"
                ),
                CCMVector(
                    keySize = 256,
                    nonceLen = 13,
                    icvLen = 17,
                    oid = NISTObjectIdentifiers.id_aes256_CCM,
                    ex = InvalidCipherTextException::class.java,
                    exMsg = "Error during cipher finalisation"
                )
            )



            for (vector in vectors) {

                if (vector.ex == null) {
                    validateCCMSpec(vector.keySize, vector.nonceLen, vector.icvLen, vector.oid)
                } else {
                    val ex = assertThrows(vector.ex) {
                        validateCCMSpec(vector.keySize, vector.nonceLen, vector.icvLen, vector.oid)
                    }
                    assertEquals(vector.exMsg, ex.message)
                }
            }
        }


        @Test
        fun `test with tagSize`() {
            val IV = ByteArray(16)
            val aad = ByteArray(10)
            val message = "test".toByteArray()

            KCryptoServices.secureRandom.nextBytes(IV)

            KCryptoServices.symmetricKey(AESGenSpec(128)).apply {
                val algID = AlgorithmIdentifier(NISTObjectIdentifiers.id_aes128_CCM, CCMParameters(IV, 16))
                val toTestSpec = CCMSpec(IV, 128).validatedSpec(this)
                assertArrayEquals(algID.getEncoded(), toTestSpec.algorithmIdentifier.getEncoded())
            }

            KCryptoServices.symmetricKey(AESGenSpec(192)).apply {
                val algID = AlgorithmIdentifier(NISTObjectIdentifiers.id_aes192_CCM, CCMParameters(IV, 16))
                val toTestSpec = CCMSpec(IV, 128).validatedSpec(this)
                assertArrayEquals(algID.getEncoded(), toTestSpec.algorithmIdentifier.getEncoded())
            }

            KCryptoServices.symmetricKey(AESGenSpec(256)).apply {
                val algID = AlgorithmIdentifier(NISTObjectIdentifiers.id_aes256_CCM, CCMParameters(IV, 16))
                val toTestSpec = CCMSpec(IV, 128).validatedSpec(this)
                assertArrayEquals(algID.getEncoded(), toTestSpec.algorithmIdentifier.getEncoded())
            }

        }


    }

}