import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.pkcs.RSAPrivateKey
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.KeyType
import org.bouncycastle.kcrypto.pkcs.PKCS8EncryptedPrivateKey
import org.bouncycastle.kcrypto.pkcs.PKCS8EncryptedPrivateKeyBuilder
import org.bouncycastle.kcrypto.spec.asymmetric.RSAGenSpec
import org.bouncycastle.kcrypto.spec.kdf.ScryptSpec
import org.bouncycastle.kcrypto.spec.symmetric.AESGenSpec
import org.bouncycastle.kcrypto.spec.symmetric.GCMSpec
import org.bouncycastle.kutil.readPEMObject
import org.bouncycastle.kutil.writePEMObject
import org.bouncycastle.pkcs.PKCSException
import org.bouncycastle.util.Arrays
import org.bouncycastle.util.encoders.Base64
import org.bouncycastle.util.encoders.Hex
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.io.ByteArrayOutputStream
import java.io.File
import java.math.BigInteger
import java.security.SecureRandom
import java.security.Security
import java.security.spec.RSAKeyGenParameterSpec
import kotlin.experimental.xor

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PKCS8Tests {

    init {
        initProvider()
    }

    @Test
    fun `round trip`() {
        val key = KCryptoServices.symmetricKey(AESGenSpec(256))
        val bOut = ByteArrayOutputStream()
        val aeadEncryptor = key.encryptor(GCMSpec(Hex.decode("000102030405060708090a0b"), 128)).outputEncryptor(bOut)
        val smallKp =
            KCryptoServices.signingKeyPair(RSAGenSpec(1024, RSAKeyGenParameterSpec.F0, SecureRandom()))

        val wrapCipher = key.encryptor(GCMSpec(aeadEncryptor.algorithmIdentifier))


        val builder = PKCS8EncryptedPrivateKeyBuilder(smallKp.signingKey)

        val encInfo = builder.build(wrapCipher)

        var originalKey = encInfo.privateKey(key, KeyType.DECRYPTION)

        File("/tmp/priv.pem").writePEMObject(encInfo)

        val pemPriv = File("/tmp/priv.pem").readPEMObject<PKCS8EncryptedPrivateKey>() as PKCS8EncryptedPrivateKey

        val recoveredKey = pemPriv.privateKey(key, KeyType.DECRYPTION)

        assert(Arrays.areEqual(originalKey.encoding, recoveredKey.encoding))

    }

    @Test
    fun `vandalised encoding`() {
        val key = KCryptoServices.symmetricKey(AESGenSpec(256))
        val bOut = ByteArrayOutputStream()
        val aeadEncryptor = key.encryptor(GCMSpec(Hex.decode("000102030405060708090a0b"), 128)).outputEncryptor(bOut)
        val smallKp =
            KCryptoServices.signingKeyPair(RSAGenSpec(1024, RSAKeyGenParameterSpec.F0, SecureRandom()))

        val wrapCipher = key.encryptor(GCMSpec(aeadEncryptor.algorithmIdentifier))


        val builder = PKCS8EncryptedPrivateKeyBuilder(smallKp.signingKey)

        val encInfo = builder.build(wrapCipher)


        val raw = encInfo.encoding
        // Vandalise the message
        raw[raw.size - 1] = raw[raw.size - 1] xor 1

        val recoveredEncoding = PKCS8EncryptedPrivateKey(raw)


        assertThrows(
            PKCSException::class.java,
            {
                recoveredEncoding.privateKey(key, KeyType.DECRYPTION)

            },
            "unable to read encrypted data: javax.crypto.AEADBadTagException: Error finalising cipher data: mac check in GCM failed"
        )
    }


    @Test
    fun `incorrect message`() {


        val key = KCryptoServices.symmetricKey(AESGenSpec(256))
        var bOut = ByteArrayOutputStream()
        val aeadEncryptor = key.encryptor(GCMSpec(Hex.decode("000102030405060708090a0b"), 128)).outputEncryptor(bOut)
        val smallKp =
            KCryptoServices.signingKeyPair(RSAGenSpec(1024, RSAKeyGenParameterSpec.F0, SecureRandom()))
        var wrapCipher = key.encryptor(GCMSpec(aeadEncryptor.algorithmIdentifier))

        bOut = ByteArrayOutputStream()
        var outEnc = wrapCipher.outputEncryptor(bOut)

        val builder = PKCS8EncryptedPrivateKeyBuilder(smallKp.signingKey)

        val encInfo = builder.build(wrapCipher)


        wrapCipher = key.encryptor(GCMSpec(aeadEncryptor.algorithmIdentifier))
        outEnc = wrapCipher.outputEncryptor(bOut)


        outEnc.use {
            it.encStream.write(encInfo.encoding)
        }

        //
        // Put the wrong oid on it.
        //
        val brokenKey = PKCS8EncryptedPrivateKey(
            EncryptedPrivateKeyInfo(
                AlgorithmIdentifier(
                    NISTObjectIdentifiers.id_aes192_CCM,
                    encInfo.encryptionAlgorithm.parameters
                ), bOut.toByteArray()
            )
        )

        assertThrows(
            PKCSException::class.java,
            {
                brokenKey.privateKey(key, KeyType.DECRYPTION)

            },
            "unable to read encrypted data: javax.crypto.AEADBadTagException: Error finalising cipher data: mac check in GCM failed"
        )

    }


    private val modulus = BigInteger(
        "b6ce33ccbf839457b0d32487b6c807bca584f85c627466b787fc09d0b1f73d97c9a381eca20e0ba851d317a8964327fa0010de76c" +
                "6c0facb83f13612752d166b49d9ba272c38c9a4ed71a94ea69f7bbdc63d7a5c5d3f3c039223e4ac1bb5d433c6bf01e68364a7ef4f" +
                "061f7cdfba82fa471bb1444b2034e53cc9c3e402a8fa89", 16
    )


    private val scryptKey = Base64.decode(
        "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgqMEkeM4LztEWVfpUNZg0ScpuN+8VPvcPfPY7Sf185tCgCgYIKoZIzj0DAQehR" +
                "ANCAAS3C+b2c+KBmyFdMGD//nnR1GzSrw7iHKPcibbO01uvKCEZWao+f85Ljhagsx/iRVMrVND5kgTwGaE2yvQ1JNwS"
    )


    @Test

    fun testGCMwithPMKDF2GeneratedfromBCApi() {


        val vec = Base64.decode(
            "MIIDBDB0BgkqhkiG9w0BBQ0wZzBBBgkqhkiG9w0BBQwwNAQg/awZCFv56t4g6GZVGCsk/thozmMmS0Sh0kmIiOEHFPECAgQAMAwGCCqGS" +
                    "Ib3DQIJBQAwIgYJYIZIAWUDBAEuMBUEEDExERBgYfRKlw8bkKNtad4CARAEggKK99QeQWbgNlofs704V2YsYXoeFb2TWujcwz" +
                    "ZkDR/IwQzsJ00RFiXVs6OB6Kbb9ous7YrEB2xMDuksTuR+DGv+mntLzK/ePQuLX/xLXVQ6B01C3m5vdlAeD1IuMl/ifoEHmVb" +
                    "uNDdQeVRgSJvmY054N9q4dthM7Ao2vkh1PTu0L1AUTLtjwCK4jyP2jajMU2YefcH7X5n8MZaA1Sj6zMDE6M+pK0qSaiJBNQdR" +
                    "im/8kMpYCHIGikNOhen+LQxsa1u2tVQvA7eXrn1uLxD/q6qgb0GhF5XRIG2EULkAczDG3ji1yjGD/znTTko0QzBaJ9GK6/20N" +
                    "jzX33n37U+op+yE+oQfXS1rMQB0xbx2nTgU6D0Uk6tiO3wvaQPiYxkUOLTPrThhbYUSt5rgN0RdinX7/OpzWesNaEUPqasyAl" +
                    "+5XYA9r9E2o1Av2lUtahOUcLeD6qKOCEgF1A7Mq2kmHzbyKbeUgN59whHmFzNJzgTNacbm6UtCQnAJFuuAIZifMgtjGNQJUkh" +
                    "j7lBybwjsXXpDUDdL6MykpOEBQqQNzFCajTDEBml0BjfjIm+tnrCLCKShYsem9+sBn2YQXVdVuEJzPavO2GVzWyQTbO5fSp8o" +
                    "hvFK9nAUHcCHFyEdMvRMqdNYF7gGLSUhzrggquvEA1RB3ZfEfWnCuEebGhdDv1cxY8DBRda0LnDNOjE0uh0JrMXPBnn7lo9Ob" +
                    "3Cf2bLx2z205CZctuni1nQuyrMxVElry6sUhFXFO+VnbnGmdu7kw9q1w+zDdAcP5duIV65cKgqKdXE1Dz0ZN6GjIIK5OGtR3O" +
                    "ty91CFeLhMXxMSKGhXm05iSJ05AGz313eb9bMwtIMO8esRJ6Zme2Sq+l4="
        )

        val ecInfo = EncryptedPrivateKeyInfo.getInstance(vec)


        val sk = PKCS8EncryptedPrivateKey(ecInfo)
        assertTrue(sk.isPBEBased)

        val dc = sk.privateKey(
            sk.pbkdf?.symmetricKey("hello".toCharArray()) ?: throw IllegalStateException("no key"),
                KeyType.DECRYPTION
        )

        val pkInfo = PrivateKeyInfo.getInstance(dc.encoding)
        val k = RSAPrivateKey.getInstance(pkInfo.parsePrivateKey())
        assertEquals(modulus, k.modulus)
    }

    @Test
    fun testScryptGeneratedFromBCAPI() {

        val vector = Base64.decode(
            """
                MIIBDDBhBgkqhkiG9w0BBQ0wVDAuBgkrBgEEAdpHBAswIQQUBXpll8qESwrB7nVJgzZNaeuZmI0CAxAAAAIBCAIBATAiBglghk
                gBZQMEAS4wFQQQxDteTxEPhVPFjDVfgHaXZQIBEASBpnmculAlqwVyTuM6Grim3LNAkXd0XCrhY9OHuINgv3uuivymyVssM6dS
                Q/BnPka0Dd8iuhSffuFnsS7x5yI2UqTdx7Bvi9fqz9gljVa7h9QIlItiOk8VKjBuN6oERyy62Y5hr2JFZbzrQDjtWNB5LCCvzY
                as34IR9vY3PtB9LbVT4EtzN0sJZ44Z9/1VksnlK+Zs5Is/d2UbRvwFnDCi2Yj/3V4NYBI=
            """.trimIndent()
        )


        val ecInfo = EncryptedPrivateKeyInfo.getInstance(vector)

        val sk = PKCS8EncryptedPrivateKey(ecInfo)
        assertTrue(sk.isPBEBased)

        val dc = sk.privateKey(
            sk.pbkdf?.symmetricKey("Rabbit".toCharArray()) ?: throw IllegalStateException("no key"),
            KeyType.SIGNING
        )

        val pki = PrivateKeyInfo.getInstance(dc.encoding)

        assertTrue(Arrays.areEqual(scryptKey, pki.encoded))
    }


    @Test
    fun testPBKDF2GeneratedFromBCAPI() {


        val vec = Base64.decode(
            """
                MIIC6zBdBgkqhkiG9w0BBQ0wUDBBBgkqhkiG9w0BBQwwNAQgP7T4nYtkSNKRd9t4yr81ygAOMvsYY+Y22bTEU9DRuA8CAgQAMAwGC
                CqGSIb3DQIJBQAwCwYJYIZIAWUDBAEIBIICiHypsKWxTJ9C+ciHwk6u5/W09idwNEQJB2NrWBNgKXDGjzl+UHu8ZG1FfHu3UE5f4
                vmopXg6mW8TGhDlNsEi47N21yD85UVbMforHxAUT/IH0V7FrsJEbkHJWL/nAiPnid7eDew6aOCh/i1nW4F8SQi05pe5c03L8UUvj
                2R7+FsHGQ/33/n95px1Ch5PTctYQkNpsAbySiIVJYXOX4pJZQfHQsG13uYkfXvmBjiHs+xo/O+k/Pf127FrvV09gtM9sYD/xL6dH
                PTTzdESuR93Kd+cxb0jPADz3r0FHX9UD6rLKXaQLTEE7pdZ6eZJp+VNkBlcrrvumePtQ95Polz5+Fd5ZVr5UDP/uP0Aq8f5s+MwF
                esNUjk9uLa5qMtTnpI4rXoDrAp7QAQALxL2RqlIEeYJkSH4j3371WDD2BR12uQ9FoOdIBS3Zav3MebTxpnR+1boFDqRYTB1GAz0W
                iZZhdN+21kxkwCZNhMrABv0ByxwI6Kpfkzmk3kU0ObOHUFf9IpRi2Q5GTYd/faqXBqy/wpEeFKiOQImy3GVu6SZrBh4BMFwnoWSF
                kUOvZHWonZTHZWL3no2ajPboLFf3a4yQKlXlfP+em0AwpcuRDrY4LDK34RNq6n18jpY80N9xKtFotdSpE2c4vOOlNwiahMM9ODDw
                P2ovg4eJpN+F0+UuzMUgXLALlR4jdSp4boI42XxKIkfpiM5zBz49Cjgsdl0YLpBEcyeM2V3aVE5WEsRY/FNCKJTyADCaqqbbBk3R
                Q4yZtr6yNzzXS5n+CPsLv4y9l8gHZTTcsk+K52cDlHqOENflbJWBQ1lEBH0U7xrWzx4RmSsekOXrVAHnUT4GHbkP23q5UK5vcXWWw==
            """.trimIndent()
        )

        val ecInfo = EncryptedPrivateKeyInfo.getInstance(vec)
        val sk = PKCS8EncryptedPrivateKey(ecInfo)
        assertTrue(sk.isPBEBased)

        val dc = sk.privateKey(
            sk.pbkdf?.symmetricKey("hello".toCharArray()) ?: throw IllegalStateException("no key"),
                KeyType.DECRYPTION
        )


        val pkInfo = Base64.decode(
            "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALbOM8y/g5RXsNMkh7bIB7ylhPhcYnRmt4f8CdCx9z2XyaOB7KIOC6hR" +
                    "0xeolkMn+gAQ3nbGwPrLg/E2EnUtFmtJ2bonLDjJpO1xqU6mn3u9xj16XF0/PAOSI+SsG7XUM8a/AeaDZKfvTwYffN+6gvpHG7FESyA0" +
                    "5TzJw+QCqPqJAgMBAAECgYAMQxCeb0o4LRmjUBP6YriCIugkcK35+NneuT0/TnCzJPdVjGV/CUom5DYwpBJQNuJCFt+VQAe5yuTyzRm3" +
                    "2mpicusxKsMHqJRJFWIQ5ztuRehGF1KB+NPze7GxWVB2vRWJQQhlgq/nRsAjWoUfxbFkKBlNPhUnLm1klwBptpqpcQJBAOBiAnrrraBu" +
                    "3Lc9B8QtCdEAIr5LYyWYd3jSvyTt04OI8Q3l7zG9omKpdIskGNu7n5RRYixsNXAVCaiHsyHHCO8CQQDQkGdtlH5fQZ2PJVSNZ6RlDhUq" +
                    "6RGqajnkXw/sK1GR388FGqc9xTB9Eu1vg7ywlsuWSWpiCe/q+1nGVJufLAQHAkEAyTba5oQGNYJ1J1Txa/i/fs7SWTedd49cQ9spUeJ7" +
                    "9M6O7FmvwDlAL52qR0Rdjl6YYhcBJLj8yr/y41CdUML9vQJAYGDqurOtNj2vHrAkg3fKezxnwb2UgUi3WfYn+H4IIr3m/7fSYvQVtSai" +
                    "/C5Hat80U0230HhBGzhtwv3kMEj5zwJAViD4ceQRYyC+G2z5fyFz8Ca6sjDB9LwY0YEOFxR+3nqtteJI2vgITl4HrrnTRGuiVSY6pqkX" +
                    "hX2DZcWDZMieLA=="
        )

        assertTrue(Arrays.areEqual(pkInfo, dc.encoding))
    }


    @Test
    fun testScryptEncryption() {


        val builder = PKCS8EncryptedPrivateKeyBuilder(scryptKey)
        val sc = ScryptSpec(20, 1048576, 8, 1)

        val keyq = KCryptoServices.pbkdf(sc, AESGenSpec(256)).symmetricKey("Hello, world!".toCharArray())

        val wrapCipher = keyq.encryptor(GCMSpec(Hex.decode("000102030405060708090a0b"), 128))


        val encInfo = builder.build(wrapCipher)

        assertTrue(encInfo.isPBEBased)

        val k = encInfo.pbkdf?.symmetricKey("Hello, world!".toCharArray())
            ?: throw IllegalStateException("should not be null")
        assertNotNull(k)

        val sKey = encInfo.privateKey(k, KeyType.SIGNING)

        assertTrue(Arrays.areEqual(scryptKey, sKey.encoding))
    }


}