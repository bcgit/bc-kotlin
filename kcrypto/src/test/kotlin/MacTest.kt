import org.bouncycastle.kcrypto.spec.AuthKeyGenSpec
import org.bouncycastle.kcrypto.spec.symmetric.*
import org.bouncycastle.util.encoders.Hex
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class MacTest {

    val specs =
        listOf(HMacSHA1GenSpec(), HMacSHA224GenSpec(), HMacSHA256GenSpec(), HMacSHA384GenSpec(), HMacSHA512GenSpec())

    init {
        initProvider()
    }

    @Test
    fun `basic digest test`() {

        val input = ByteArray(100)

        specs.forEach { spec ->
            KCryptoServices.secureRandom.nextBytes(input)
            val key = KCryptoServices.macKey(spec)

            val code = key.macCalculator(HMacSpec()).apply {
                stream.use { it.write(input) }
            }.mac()


            assertTrue(
                key.macVerifier(HMacSpec()).apply {
                    stream.use { it.write(input) }
                }.verifies(code)
            )
        }
    }

    @Test
    fun `non decode`() {
        val input = ByteArray(100)
        var ctr = 1;
        for (spec in specs) {
            KCryptoServices.secureRandom.nextBytes(input)
            val keyIn = KCryptoServices.macKey(spec)


            val code = keyIn.macCalculator(HMacSpec()).apply {
                stream.use { it.write(input) }
            }.mac()


            for (wrongSpec in specs) {
                if (wrongSpec == spec) {
                    continue
                }

                val keyOut = KCryptoServices.macKey(wrongSpec)
                assertFalse(
                    keyOut.macVerifier(HMacSpec()).apply {
                        stream.use { it.write(input) }
                    }.verifies(code)
                )
            }
        }
    }


    data class Vector(
        val spec: AuthKeyGenSpec,
        val value: ByteArray,
        val rounds: Int = 1,
        val key: ByteArray,
        val result: ByteArray,
        val validates: Boolean = true
    )


    @Test
    fun `kat tests`() {

        val vector = listOf<Vector>(
            Vector(
                spec = HMacSHA1GenSpec(),
                value = "a".toByteArray(),
                rounds = 1,
                key = Hex.decode("63cc6b9ab11ed6fe6fcaf3028a28b3c0d4188e25"),
                result = Hex.decode("d8b8e7c2735d705c104fec8c4c4706489e066641")
            ),
            Vector(
                spec = HMacSHA1GenSpec(),
                value = "abc".toByteArray(),
                rounds = 1,
                key = Hex.decode("28fa0d7783c546983acebfb76796d9982aa9e904"),
                result = Hex.decode("dd34c1d838831945e9488f6a85faa7c66473679c")
            ),
            Vector(
                spec = HMacSHA1GenSpec(),
                value = "abcde".toByteArray(),
                rounds = 1000,
                key = Hex.decode("292a179d3f54129fb431deab301cbd00e4d8a1c3"),
                result = Hex.decode("c2dfd68aa06e3a8edfa7bb54f79829a64b73fe0e")
            ),
            Vector(
                spec = HMacSHA1GenSpec(),
                value = "abcde".toByteArray(),
                rounds = 1,
                key = Hex.decode("292a179d3f54129fb431deab301cbd00e4d8a1c3"),
                result = Hex.decode("c2dfd68aa06e3a8edfa7bb54f79829a64b73fe0e"),
                validates = false
            ),


            Vector(
                spec = HMacSHA224GenSpec(),
                value = "a".toByteArray(),
                rounds = 1,
                key = Hex.decode("7f0b74527ccd699c3aaece5ebeb116fc17e918cb71105e50f09aa7d1"),
                result = Hex.decode("dea4c71e32bb29095dc74fb3d442ee1168fe0a360edb46d8d6d2d4ae")
            ),
            Vector(
                spec = HMacSHA224GenSpec(),
                value = "abc".toByteArray(),
                rounds = 1,
                key = Hex.decode("fd0afa2658575b1fd623dc1916efae50ce2abb6c97a70297dec55c47"),
                result = Hex.decode("3b83dab093518b5e3a765eb9a23489d92f696f1210ce09d43ea069dc")
            ),
            Vector(
                spec = HMacSHA224GenSpec(),
                value = "abcde".toByteArray(),
                rounds = 1000,
                key = Hex.decode("0c5317485e142897c46c0119c006af87414a0e14785139ca8875698f"),
                result = Hex.decode("753e6c600f669c7676cf7579a3558fc800daad6e20621b1c7b10b383")
            ),
            Vector(
                spec = HMacSHA224GenSpec(),
                value = "abcde".toByteArray(),
                rounds = 1,
                key = Hex.decode("0c5317485e142897c46c0119c006af87414a0e14785139ca8875698f"),
                result = Hex.decode("753e6c600f669c7676cf7579a3558fc800daad6e20621b1c7b10b383"),
                validates = false
            ),


            Vector(
                spec = HMacSHA256GenSpec(),
                value = "a".toByteArray(),
                rounds = 1,
                key = Hex.decode("6a44538876f4a149d1bfdaff34c1bdfc03c3ca074f607b6ff95ca3876325eaa1"),
                result = Hex.decode("76169a6598f3ea8e89c7f8d46ebf979306d4d9dff808e1bf7b99ebd97bf28269")
            ),
            Vector(
                spec = HMacSHA256GenSpec(),
                value = "abc".toByteArray(),
                rounds = 1,
                key = Hex.decode("93d0216280df512ca762d4eb362f59d2c660ad63a16c67a00e59b9d679142571"),
                result = Hex.decode("48d5a6605ca2dea6a38626e626164e40e6e0feec1497bdd1b44b74ce8e96e61e")
            ),
            Vector(
                spec = HMacSHA256GenSpec(),
                value = "abcde".toByteArray(),
                rounds = 1000,
                key = Hex.decode("65af1e18037b6e88fa950095f2391c2444592abf3512a6c91da708c94854d5f1"),
                result = Hex.decode("b2ea166ccaefe29e4a80dd52255641fa4a5e387f58a8b296c42b8587b56f3cea")
            ),
            Vector(
                spec = HMacSHA256GenSpec(),
                value = "abcde".toByteArray(),
                rounds = 1,
                key = Hex.decode("7465fbdbe322d3c699ffe6edc727617693ec359150ddca3e5a45d50299247a58"),
                result = Hex.decode("7465fbdbe322d3c699ffe6edc727617693ec359150ddca3e5a45d50299247a58"),
                validates = false
            ),


            Vector(
                spec = HMacSHA384GenSpec(),
                value = "a".toByteArray(),
                rounds = 1,
                key = Hex.decode("00734e2452922ce2c1e8c934819f8f113df3ab8e2ac89cf0e241f5c833e593da0170d9dba0965938c62f41fe7ebdae46"),
                result = Hex.decode("d47c2a5434664291fec35f6ff5cb5552f36d095593ab2f53e20203a88d51cc585f7e5e2554b6eb98961d42bc6ca4eea7")
            ),
            Vector(
                spec = HMacSHA384GenSpec(),
                value = "abc".toByteArray(),
                rounds = 1,
                key = Hex.decode("6c8558cf7669f180a4cb6b16ab53ac853b223582e42c93cace2514bbed399fc2c89e092bc115ea96eda91413b6602a14"),
                result = Hex.decode("dae41be5e11e5cfac4214aab86463e6c2e8f4709d575293f250d09049b29a4e6d5023ede7022e142f669b27985d4877d")
            ),
            Vector(
                spec = HMacSHA384GenSpec(),
                value = "abcde".toByteArray(),
                rounds = 1000,
                key = Hex.decode("e0b0e84e5edd39a1a1898500479ae7410c81a8b31475f3bf1c9b0f0b82659d483c5c3e1ecf284aaa156865896ccac0c3"),
                result = Hex.decode("58cf13bcbdbad083160b3cb185728909d48d5565f10dfa695cff5cf9576d04ae00866f7d2ac260e7396df23ef6155aa4")
            ),
            Vector(
                spec = HMacSHA384GenSpec(),
                value = "abcde".toByteArray(),
                rounds = 1,
                key = Hex.decode("e0b0e84e5edd39a1a1898500479ae7410c81a8b31475f3bf1c9b0f0b82659d483c5c3e1ecf284aaa156865896ccac0c3"),
                result = Hex.decode("58cf13bcbdbad083160b3cb185728909d48d5565f10dfa695cff5cf9576d04ae00866f7d2ac260e7396df23ef6155aa4"),
                validates = false
            ),

            Vector(
                spec = HMacSHA512GenSpec(),
                value = "a".toByteArray(),
                rounds = 1,
                key = Hex.decode("e3775d599a0a371322e692d0f92feb88c1fd926ff5c3603d0fd6ae3b40959201f8ceb011f5864e4a3ff5f0615bf9cefc3bd0064ee07e8011e8eba6e790345d46"),
                result = Hex.decode("6308be7d98ee94c5998e633eb4079326b6e5a85fd7475e4edcd901ca437fef0d923da778b54cb9f45afcfc0c22fbed1059a24e19df414ff1baf53f599006545f")
            ),
            Vector(
                spec = HMacSHA512GenSpec(),
                value = "abc".toByteArray(),
                rounds = 1,
                key = Hex.decode("3edd6bbaeab5c232305a6e9108e07be6cba5b308e39b2b6b4f1f3e16c89128a04a2cbc7f3e39e0e2acc69f3f5cf4d745aa52f2ee5e97a18cb2e3b6a61b688152"),
                result = Hex.decode("af88063a68013a34262ff8653d793a9ee459432ba9369e724b73ed3fcf0cdf32f52891cfda1e0fafd077c85427ac7f40f45cc84c180ed678bf976efcdae2ab5a")
            ),
            Vector(
                spec = HMacSHA512GenSpec(),
                value = "abcde".toByteArray(),
                rounds = 1000,
                key = Hex.decode("822ce75ae6ae19f41f9dd2f76a7f2c39824341e3c2beed78a0deb9f6041c48967f5ff2034252c76e83ec5975df7cb29c18fb61bd4b8afca5bb703f5d74e95a29"),
                result = Hex.decode("3ac8f14a42ee74b92b3b80138fa09a0da68abcf5aded0a7090f10d45d96f9045c4fdd2cd9b3cd79f44a9ce0ef1f9333c6b460c90e1f3ec1680173429da60cb56")
            ),
            Vector(
                spec = HMacSHA512GenSpec(),
                value = "abcde".toByteArray(),
                rounds = 1,
                key = Hex.decode("822ce75ae6ae19f41f9dd2f76a7f2c39824341e3c2beed78a0deb9f6041c48967f5ff2034252c76e83ec5975df7cb29c18fb61bd4b8afca5bb703f5d74e95a29"),
                result = Hex.decode("3ac8f14a42ee74b92b3b80138fa09a0da68abcf5aded0a7090f10d45d96f9045c4fdd2cd9b3cd79f44a9ce0ef1f9333c6b460c90e1f3ec1680173429da60cb56"),
                validates = false
            )


        )

        vector.withIndex().forEach { vector ->
            val cnt = vector.index

            with(vector.value) {
                //                val vec = this
                val key = KCryptoServices.macKey(this.key, this.spec.authType)
                val res = key.macVerifier(HMacSpec()).apply {
                    stream.use { str ->
                        (0..this@with.rounds - 1).forEach { _ ->
                            str.write(this@with.value)
                        }
                    }
                }.verifies(this.result)

                assertEquals(this.validates, res, "Item: " + cnt)

            }
        }


    }

}