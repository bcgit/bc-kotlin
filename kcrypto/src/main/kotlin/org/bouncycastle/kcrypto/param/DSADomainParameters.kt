package org.bouncycastle.kcrypto.param

//import org.bouncycastle.crypto.asymmetric.DSAValidationParameters
import org.bouncycastle.util.Arrays
import org.bouncycastle.util.encoders.Hex
import java.math.BigInteger

/**
 * Container class for DSA domain parameters.
 */
class DSADomainParameters {
    val g: BigInteger
    val q: BigInteger
    val p: BigInteger
    val validationParameters: DSAValidationParameters?

    constructor(
            p: BigInteger,
            q: BigInteger,
            g: BigInteger) {
        this.g = g
        this.p = p
        this.q = q
        this.validationParameters = null;
    }

    constructor(
            p: BigInteger,
            q: BigInteger,
            g: BigInteger,
            params: DSAValidationParameters) {
        this.g = g
        this.p = p
        this.q = q
        this.validationParameters = params
    }

    override fun equals(other: Any?): Boolean {
        if (other is DSADomainParameters) {
            return other.p.equals(p) && other.q.equals(q) && other.g.equals(g)
        }

        return false
    }

    override fun hashCode(): Int {
        var result = g.hashCode()
        result = 31 * result + p.hashCode()
        result = 31 * result + q.hashCode()
        return result
    }

    companion object {
        val DEF_1024 = DSADomainParameters(
                BigInteger("fd7f53811d75122952df4a9c2eece4e7f611b7523cef4400c31e3f80" +
                        "b6512669455d402251fb593d8d58fabfc5f5ba30f6cb9b556cd7813b" +
                        "801d346ff26660b76b9950a5a49f9fe8047b1022c24fbba9d7feb7c6" +
                        "1bf83b57e7c6a8a6150f04fb83f6d3c51ec3023554135a169132f675" +
                        "f3ae2b61d72aeff22203199dd14801c7", 16),
                BigInteger("9760508f15230bccb292b982a2eb840bf0581cf5", 16),
                BigInteger("f7e1a085d69b3ddecbbcab5c36b857b97994afbbfa3aea82f9574c0b" +
                        "3d0782675159578ebad4594fe67107108180b449167123e84c281613" +
                        "b7cf09328cc8a6e13c167a8b547c8d28e0a3ae1e2bb3a675916ea37f" +
                        "0bfa213562f1fb627a01243bcca4f1bea8519089a883dfe15ae59f06" +
                        "928b665e807b552564014c3bfecf492a", 16),
                DSAValidationParameters(Hex.decode("8d5155894229d5e689ee01e6018a237e2cae64cd"), 92))

        val DEF_2048 = DSADomainParameters(
                BigInteger("95475cf5d93e596c3fcd1d902add02f427f5f3c7210313bb45fb4d5b" +
                        "b2e5fe1cbd678cd4bbdd84c9836be1f31c0777725aeb6c2fc38b85f4" +
                        "8076fa76bcd8146cc89a6fb2f706dd719898c2083dc8d896f84062e2" +
                        "c9c94d137b054a8d8096adb8d51952398eeca852a0af12df83e475aa" +
                        "65d4ec0c38a9560d5661186ff98b9fc9eb60eee8b030376b236bc73b" +
                        "e3acdbd74fd61c1d2475fa3077b8f080467881ff7e1ca56fee066d79" +
                        "506ade51edbb5443a563927dbc4ba520086746175c8885925ebc64c6" +
                        "147906773496990cb714ec667304e261faee33b3cbdf008e0c3fa906" +
                        "50d97d3909c9275bf4ac86ffcb3d03e6dfc8ada5934242dd6d3bcca2" +
                        "a406cb0b", 16),
                BigInteger("f8183668ba5fc5bb06b5981e6d8b795d30b8978d43ca0ec572e37e09939a9773", 16),
                BigInteger("42debb9da5b3d88cc956e08787ec3f3a09bba5f48b889a74aaf53174" +
                        "aa0fbe7e3c5b8fcd7a53bef563b0e98560328960a9517f4014d3325f" +
                        "c7962bf1e049370d76d1314a76137e792f3f0db859d095e4a5b93202" +
                        "4f079ecf2ef09c797452b0770e1350782ed57ddf794979dcef23cb96" +
                        "f183061965c4ebc93c9c71c56b925955a75f94cccf1449ac43d586d0" +
                        "beee43251b0b2287349d68de0d144403f13e802f4146d882e057af19" +
                        "b6f6275c6676c8fa0e3ca2713a3257fd1b27d0639f695e347d8d1cf9" +
                        "ac819a26ca9b04cb0eb9b7b035988d15bbac65212a55239cfc7e58fa" +
                        "e38d7250ab9991ffbc97134025fe8ce04c4399ad96569be91a546f49" +
                        "78693c7a", 16),
                DSAValidationParameters(Hex.decode("b0b4417601b59cbc9d8ac8f935cadaec4f5fbb2f23785609ae466748d9b5a536"), 497))
    }
}

/**
 * Validation parameters for confirming DSA parameter generation.
 *
 * @param seed the seed value.
 * @param counter  (p, q) counter - -1 if not avaliable.
 * @param usageIndex the usage index.
 */
class DSAValidationParameters(private val _seed: ByteArray, val counter: Int = -1, val usageIndex: Int = -1) {

    val seed get() = Arrays.clone(_seed)

    override fun hashCode(): Int {
        var code = this.counter

        code += 37 * Arrays.hashCode(seed)
        code += 37 * usageIndex

        return code
    }

    override fun equals(other: Any?): Boolean {
        if (other is DSAValidationParameters) {

            return (this.counter == other.counter)
                    && (this.usageIndex == other.usageIndex)
                    && Arrays.areEqual(this.seed, other.seed)
        }

        return false
    }
}
