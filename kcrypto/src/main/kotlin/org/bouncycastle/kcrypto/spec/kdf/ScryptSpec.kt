package org.bouncycastle.kcrypto.spec.kdf

import KCryptoServices
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.spec.PBKDFAlgSpec
import java.math.BigInteger


/**
 * "ESS" Crypt key derivation specification
 */
class ScryptSpec : PBKDFAlgSpec<AlgorithmIdentifier> {
    val salt: ByteArray
    val costParameter: Int
    val blockSize: Int
    val parallelizationParameter: Int
    override val algorithmIdentifier: AlgorithmIdentifier

    constructor(saltLength: Int, costParameter: Int, blockSize: Int, parallelizationParameter: Int) {
        this.salt = ByteArray(saltLength)
        KCryptoServices.secureRandom.nextBytes(salt)

        this.costParameter = costParameter
        this.blockSize = blockSize
        this.parallelizationParameter = parallelizationParameter


        val params =
            Class.forName("org.bouncycastle.asn1.misc.ScryptParams")
                .getConstructor(ByteArray::class.java, Int::class.java, Int::class.java, Int::class.java)
                .newInstance(salt, costParameter, blockSize, parallelizationParameter) as ASN1Encodable


        algorithmIdentifier = AlgorithmIdentifier(MiscObjectIdentifiers.id_scrypt, params)
    }

    constructor(salt: ByteArray, costParameter: Int, blockSize: Int, parallelizationParameter: Int) {
        this.salt = salt
        this.costParameter = costParameter
        this.blockSize = blockSize
        this.parallelizationParameter = parallelizationParameter

        val params =
            Class.forName("org.bouncycastle.asn1.misc.ScryptParams")
                .getConstructor(ByteArray::class.java, Int::class.java, Int::class.java, Int::class.java)
                .newInstance(salt, costParameter, blockSize, parallelizationParameter) as ASN1Encodable

        algorithmIdentifier = AlgorithmIdentifier(MiscObjectIdentifiers.id_scrypt, params)
    }

    private fun <T> getter(key: String, instance: Any): T {
        return instance::class.java.getMethod("get" + key).invoke(instance) as T
    }

    constructor(algorithmIdentifier: AlgorithmIdentifier) {

        val params =
            Class.forName("org.bouncycastle.asn1.misc.ScryptParams")
                .getMethod("getInstance", Any::class.java)
                .invoke(null, algorithmIdentifier.parameters)


        //val params = ScryptParams.getInstance(algorithmIdentifier.parameters)

        this.salt = getter("Salt", params)
        this.costParameter =
            (getter("CostParameter", params) as BigInteger).intValueExact() //  params.costParameter.intValueExact()
        this.blockSize =
            (getter("BlockSize", params) as BigInteger).intValueExact()//   params.blockSize.intValueExact()
        this.parallelizationParameter = (getter(
            "ParallelizationParameter",
            params
        ) as BigInteger).intValueExact()//    params.parallelizationParameter.intValueExact()

        this.algorithmIdentifier = algorithmIdentifier
    }
}