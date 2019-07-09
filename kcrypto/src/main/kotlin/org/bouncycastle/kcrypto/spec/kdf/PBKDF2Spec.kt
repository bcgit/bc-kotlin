package org.bouncycastle.kcrypto.spec.kdf

import KCryptoServices
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.pkcs.PBKDF2Params
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.AuthenticationKey
import org.bouncycastle.kcrypto.KeyType
import org.bouncycastle.kcrypto.spec.PBKDFAlgSpec
import org.bouncycastle.kcrypto.spec.symmetric.*

internal fun findPrfAlgId(prfTemplate: KeyType<out Any>): AlgorithmIdentifier
{
    when (prfTemplate) {
        HMacSHA1GenSpec.authType -> return AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA1, DERNull.INSTANCE)
        HMacSHA224GenSpec.authType -> return AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA224, DERNull.INSTANCE)
        HMacSHA256GenSpec.authType -> return AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256, DERNull.INSTANCE)
        HMacSHA384GenSpec.authType -> return AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA384, DERNull.INSTANCE)
        HMacSHA512GenSpec.authType -> return AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA512, DERNull.INSTANCE)
        else -> throw IllegalStateException("unknown HMac template")
    }
}

/**
 * Password Based PBKDF 2 Specification.
 */
class PBKDF2Spec: PBKDFAlgSpec<AlgorithmIdentifier>
{
    val salt: ByteArray
    val iterationCount: Int
    val hashAlg: AlgorithmIdentifier
    override val algorithmIdentifier: AlgorithmIdentifier

    constructor(saltLength: Int, iterationCount: Int, prfTemplate: KeyType<AuthenticationKey>)
    {
        this.salt = ByteArray(saltLength)
        this.iterationCount = iterationCount
        this.hashAlg = findPrfAlgId(prfTemplate)
        KCryptoServices.secureRandom.nextBytes(salt)

        val params = PBKDF2Params(
                salt,
                iterationCount,
                hashAlg)

        algorithmIdentifier = AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2, params)
    }

    constructor(salt: ByteArray, iterationCount: Int, prfTemplate: KeyType<AuthenticationKey>)
    {
        this.salt = salt
        this.iterationCount = iterationCount
        this.hashAlg = findPrfAlgId(prfTemplate)

        val params = PBKDF2Params(
                salt,
                iterationCount,
                hashAlg)

        algorithmIdentifier = AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2, params)
    }

    constructor(algorithmIdentifier: AlgorithmIdentifier)
    {
        val params = PBKDF2Params.getInstance(algorithmIdentifier.parameters)

        this.salt = params.salt
        this.iterationCount = params.iterationCount.intValueExact()
        this.hashAlg = params.prf
        this.algorithmIdentifier = algorithmIdentifier
    }
}