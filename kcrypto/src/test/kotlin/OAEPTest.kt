import org.bouncycastle.kcrypto.Digest
import org.bouncycastle.kcrypto.KeyType
import org.bouncycastle.kcrypto.spec.asymmetric.OAEPSpec
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.math.BigInteger
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.RSAPrivateCrtKeySpec
import java.security.spec.RSAPublicKeySpec
import javax.crypto.Cipher
import kotlin.experimental.xor

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class OAEPTest {

    private val pubKeySpec = RSAPublicKeySpec(
            BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
            BigInteger("11", 16))

    private val privKeySpec = RSAPrivateCrtKeySpec(
            BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
            BigInteger("11", 16),
            BigInteger("9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89", 16),
            BigInteger("c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb", 16),
            BigInteger("f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5", 16),
            BigInteger("b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391", 16),
            BigInteger("d3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd", 16),
            BigInteger("b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19", 16))


    internal var pub2048KeySpec = RSAPublicKeySpec(
            BigInteger("a7295693155b1813bb84877fb45343556e0568043de5910872a3a518cc11e23e2db74eaf4545068c4e3d258a2718fbacdcc3eafa457695b957e88fbf110aed049a992d9c430232d02f3529c67a3419935ea9b569f85b1bcd37de6b899cd62697e843130ff0529d09c97d813cb15f293751ff56f943fbdabb63971cc7f4f6d5bff1594416b1f5907bde5a84a44f9802ef29b43bda1960f948f8afb8766c1ab80d32eec88ed66d0b65aebe44a6d0b3c5e0ab051aaa1b912fbcc17b8e751ddecc5365b6db6dab0020c3057db4013a51213a5798a3aab67985b0f4d88627a54a0f3f0285fbcb4afdfeb65cb153af66825656d43238b75503231500753f4e421e3c57", 16),
            BigInteger("10001", 16))

    internal var priv2048KeySpec = RSAPrivateCrtKeySpec(
            BigInteger("a7295693155b1813bb84877fb45343556e0568043de5910872a3a518cc11e23e2db74eaf4545068c4e3d258a2718fbacdcc3eafa457695b957e88fbf110aed049a992d9c430232d02f3529c67a3419935ea9b569f85b1bcd37de6b899cd62697e843130ff0529d09c97d813cb15f293751ff56f943fbdabb63971cc7f4f6d5bff1594416b1f5907bde5a84a44f9802ef29b43bda1960f948f8afb8766c1ab80d32eec88ed66d0b65aebe44a6d0b3c5e0ab051aaa1b912fbcc17b8e751ddecc5365b6db6dab0020c3057db4013a51213a5798a3aab67985b0f4d88627a54a0f3f0285fbcb4afdfeb65cb153af66825656d43238b75503231500753f4e421e3c57", 16),
            BigInteger("10001", 16),
            BigInteger("65dad56ac7df7abb434e4cb5eeadb16093aa6da7f0033aad3815289b04757d32bfee6ade7749c8e4a323b5050a2fb9e2a99e23469e1ed4ba5bab54336af20a5bfccb8b3424cc6923db2ffca5787ed87aa87aa614cd04cedaebc8f623a2d2063017910f436dff18bb06f01758610787f8b258f0a8efd8bd7de30007c47b2a1031696c7d6523bc191d4d918927a7e0b09584ed205bd2ff4fc4382678df82353f7532b3bbb81d69e3f39070aed3fb64fce032a089e8e64955afa5213a6eb241231bd98d702fba725a9b205952fda186412d9e0d9344d2998c455ad8c2bae85ee672751466d5288304032b5b7e02f7e558c7af82c7fbf58eea0bb4ef0f001e6cd0a9", 16),
            BigInteger("d4fd9ac3474fb83aaf832470643609659e511b322632b239b688f3cd2aad87527d6cf652fb9c9ca67940e84789444f2e99b0cb0cfabbd4de95396106c865f38e2fb7b82b231260a94df0e01756bf73ce0386868d9c41645560a81af2f53c18e4f7cdf3d51d80267372e6e0216afbf67f655c9450769cca494e4f6631b239ce1b", 16),
            BigInteger("c8eaa0e2a1b3a4412a702bccda93f4d150da60d736c99c7c566fdea4dd1b401cbc0d8c063daaf0b579953d36343aa18b33dbf8b9eae94452490cc905245f8f7b9e29b1a288bc66731a29e1dd1a45c9fd7f8238ff727adc49fff73991d0dc096206b9d3a08f61e7462e2b804d78cb8c5eccdb9b7fbd2ad6a8fea46c1053e1be75", 16),
            BigInteger("10edcb544421c0f9e123624d1099feeb35c72a8b34e008ac6fa6b90210a7543f293af4e5299c8c12eb464e70092805c7256e18e5823455ba0f504d36f5ccacac1b7cd5c58ff710f9c3f92646949d88fdd1e7ea5fed1081820bb9b0d2a8cd4b093fecfdb96dabd6e28c3a6f8c186dc86cddc89afd3e403e0fcf8a9e0bcb27af0b", 16),
            BigInteger("97fc25484b5a415eaa63c03e6efa8dafe9a1c8b004d9ee6e80548fefd6f2ce44ee5cb117e77e70285798f57d137566ce8ea4503b13e0f1b5ed5ca6942537c4aa96b2a395782a4cb5b58d0936e0b0fa63b1192954d39ced176d71ef32c6f42c84e2e19f9d4dd999c2151b032b97bd22aa73fd8c5bcd15a2dca4046d5acc997021", 16),
            BigInteger("4bb8064e1eff7e9efc3c4578fcedb59ca4aef0993a8312dfdcb1b3decf458aa6650d3d0866f143cbf0d3825e9381181170a0a1651eefcd7def786b8eb356555d9fa07c85b5f5cbdd74382f1129b5e36b4166b6cc9157923699708648212c484958351fdc9cf14f218dbe7fbf7cbd93a209a4681fe23ceb44bab67d66f45d1c9d", 16))


    val privKey: PrivateKey
    val pubKey: PublicKey
    val priv2048Key: PrivateKey
    val pub2048Key: PublicKey

    init {
        initProvider()
        val fact = KeyFactory.getInstance("RSA", KCryptoServices._provider)
        privKey = fact.generatePrivate(privKeySpec)
        pubKey = fact.generatePublic(pubKeySpec)
        priv2048Key = fact.generatePrivate(priv2048KeySpec)
        pub2048Key = fact.generatePublic(pub2048KeySpec)
    }

    val input = byteArrayOf(0x54.toByte(), 0x85.toByte(), 0x9b.toByte(), 0x34.toByte(), 0x2c.toByte(), 0x49.toByte(), 0xea.toByte(), 0x2a.toByte())


    @Test
    fun `oaep sha1`() {

        val ct = KCryptoServices
                .encryptionKey(pubKey.encoded, KeyType.ENCRYPTION)
                .singleBlockEncryptor(OAEPSpec(Digest.SHA1))
                .encrypt(input)

        val res = KCryptoServices
                .decryptionKey(privKey.encoded, KeyType.DECRYPTION)
                .singleBlockDecryptor(OAEPSpec(Digest.SHA1))
                .decrypt(ct)

        assertArrayEquals(input, res)

        val c = Cipher.getInstance("RSA/NONE/OAEPwithSHA1andMGF1Padding", KCryptoServices._provider)

        c.init(Cipher.DECRYPT_MODE, privKey)

        val jceRes = c.doFinal(ct)

        assertArrayEquals(input, jceRes)

        ct[0] = ct[0] xor 1

        try {
            KCryptoServices
                    .decryptionKey(privKey.encoded, KeyType.DECRYPTION)
                    .singleBlockDecryptor(OAEPSpec(Digest.SHA1))
                    .decrypt(ct)
            assertTrue(false, "Must fail")
        } catch (ex: Exception) {
            // OK
        }

    }


    @Test
    fun `oaep sha224`() {

        val ct = KCryptoServices
                .encryptionKey(pub2048Key.encoded, KeyType.ENCRYPTION)
                .singleBlockEncryptor(OAEPSpec(Digest.SHA224))
                .encrypt(input)

        val res = KCryptoServices
                .decryptionKey(priv2048Key.encoded, KeyType.DECRYPTION)
                .singleBlockDecryptor(OAEPSpec(Digest.SHA224))
                .decrypt(ct)

        assertArrayEquals(input, res)

        val c = Cipher.getInstance("RSA/NONE/OAEPwithSHA224andMGF1Padding", KCryptoServices._provider)

        c.init(Cipher.DECRYPT_MODE, priv2048Key)

        val jceRes = c.doFinal(ct)

        assertArrayEquals(input, jceRes)

        ct[0] = ct[0] xor 1

        try {
            KCryptoServices
                    .decryptionKey(priv2048Key.encoded, KeyType.DECRYPTION)
                    .singleBlockDecryptor(OAEPSpec(Digest.SHA224))
                    .decrypt(ct)
            assertTrue(false, "Must fail")
        } catch (ex: Exception) {
            // OK
        }

    }

    @Test
    fun `oaep sha256`() {

        val ct = KCryptoServices
                .encryptionKey(pub2048Key.encoded, KeyType.ENCRYPTION)
                .singleBlockEncryptor(OAEPSpec(Digest.SHA256))
                .encrypt(input)

        val res = KCryptoServices
                .decryptionKey(priv2048Key.encoded, KeyType.DECRYPTION)
                .singleBlockDecryptor(OAEPSpec(Digest.SHA256))
                .decrypt(ct)

        assertArrayEquals(input, res)

        val c = Cipher.getInstance("RSA/NONE/OAEPwithSHA256andMGF1Padding", KCryptoServices._provider)

        c.init(Cipher.DECRYPT_MODE, priv2048Key)

        val jceRes = c.doFinal(ct)

        assertArrayEquals(input, jceRes)

        ct[0] = ct[0] xor 1

        try {
            KCryptoServices
                    .decryptionKey(priv2048Key.encoded, KeyType.DECRYPTION)
                    .singleBlockDecryptor(OAEPSpec(Digest.SHA256))
                    .decrypt(ct)
            assertTrue(false, "Must fail")
        } catch (ex: Exception) {
            // OK
        }


    }

    @Test
    fun `oaep sha384`() {

        val ct = KCryptoServices
                .encryptionKey(pub2048Key.encoded, KeyType.ENCRYPTION)
                .singleBlockEncryptor(OAEPSpec(Digest.SHA384))
                .encrypt(input)

        val res = KCryptoServices
                .decryptionKey(priv2048Key.encoded, KeyType.DECRYPTION)
                .singleBlockDecryptor(OAEPSpec(Digest.SHA384))
                .decrypt(ct)

        assertArrayEquals(input, res)

        val c = Cipher.getInstance("RSA/NONE/OAEPwithSHA384andMGF1Padding", KCryptoServices._provider)

        c.init(Cipher.DECRYPT_MODE, priv2048Key)

        val jceRes = c.doFinal(ct)

        assertArrayEquals(input, jceRes)
        
        ct[0] = ct[0] xor 1

        try {
            KCryptoServices
                    .decryptionKey(priv2048Key.encoded, KeyType.DECRYPTION)
                    .singleBlockDecryptor(OAEPSpec(Digest.SHA384))
                    .decrypt(ct)
            assertTrue(false, "Must fail")
        } catch (ex: Exception) {
            // OK
        }


    }

    @Test
    fun `oaep sha512`() {

        val ct = KCryptoServices
                .encryptionKey(pub2048Key.encoded, KeyType.ENCRYPTION)
                .singleBlockEncryptor(OAEPSpec(Digest.SHA512))
                .encrypt(input)

        val res = KCryptoServices
                .decryptionKey(priv2048Key.encoded, KeyType.DECRYPTION)
                .singleBlockDecryptor(OAEPSpec(Digest.SHA512))
                .decrypt(ct)

        assertArrayEquals(input, res)

        val c = Cipher.getInstance("RSA/NONE/OAEPwithSHA512andMGF1Padding", KCryptoServices._provider)

        c.init(Cipher.DECRYPT_MODE, priv2048Key)

        val jceRes = c.doFinal(ct)

        assertArrayEquals(input, jceRes)

        ct[0] = ct[0] xor 1

        try {
            KCryptoServices
                    .decryptionKey(priv2048Key.encoded, KeyType.DECRYPTION)
                    .singleBlockDecryptor(OAEPSpec(Digest.SHA512))
                    .decrypt(ct)
            assertTrue(false, "Must fail")
        } catch (ex: Exception) {
            // OK
        }


    }


}