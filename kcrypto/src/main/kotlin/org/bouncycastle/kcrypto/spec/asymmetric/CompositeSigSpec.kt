package org.bouncycastle.kcrypto.spec.asymmetric

import org.bouncycastle.asn1.iana.IANAObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.jcajce.CompositePrivateKey
import org.bouncycastle.jcajce.CompositePublicKey
import org.bouncycastle.kcrypto.BaseSigningKey
import org.bouncycastle.kcrypto.BaseVerificationKey
import org.bouncycastle.kcrypto.SigningKey
import org.bouncycastle.kcrypto.VerificationKey
import org.bouncycastle.kcrypto.spec.SigAlgSpec

val mldsa44_rsa2048_pss_sha256 = IANAObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256
val mldsa44_rsa2048_pkcs15_sha256 = IANAObjectIdentifiers.id_MLDSA44_RSA2048_PKCS15_SHA256
val mldsa44_ed25519_sha512 = IANAObjectIdentifiers.id_MLDSA44_Ed25519_SHA512
val mldsa44_ecdsa_p256_sha256 = IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256
val mldsa65_rsa3072_pss_sha512 = IANAObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA512
val mldsa65_rsa3072_pkcs15_sha512 = IANAObjectIdentifiers.id_MLDSA65_RSA3072_PKCS15_SHA512
val mldsa65_rsa4096_pss_sha512 = IANAObjectIdentifiers.id_MLDSA65_RSA4096_PSS_SHA512
val mldsa65_rsa4096_pkcs15_sha512 = IANAObjectIdentifiers.id_MLDSA65_RSA4096_PKCS15_SHA512
val mldsa65_ecdsa_p256_sha512 = IANAObjectIdentifiers.id_MLDSA65_ECDSA_P256_SHA512
val mldsa65_ecdsa_p384_sha512 = IANAObjectIdentifiers.id_MLDSA65_ECDSA_P384_SHA512
val mldsa65_ecdsa_brainpoolp256r1_sha512 = IANAObjectIdentifiers.id_MLDSA65_ECDSA_brainpoolP256r1_SHA512
val mldsa65_ed25519_sha512 = IANAObjectIdentifiers.id_MLDSA65_Ed25519_SHA512
val mldsa87_ecdsa_p384_sha256 = IANAObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA512
val mldsa87_ecdsa_brainpoolp384r1_sha512 = IANAObjectIdentifiers.id_MLDSA87_ECDSA_brainpoolP384r1_SHA512
val mldsa87_ed448_shake256 = IANAObjectIdentifiers.id_MLDSA87_Ed448_SHAKE256
val mldsa87_rsa3072_pss_sha512 = IANAObjectIdentifiers.id_MLDSA87_RSA3072_PSS_SHA512
val mldsa87_rsa4096_pss_sha512 = IANAObjectIdentifiers.id_MLDSA87_RSA4096_PSS_SHA512
val mldsa87_ecdsa_p521_sha512 = IANAObjectIdentifiers.id_MLDSA87_ECDSA_P521_SHA512

class CompositeSigSpec: SigAlgSpec {

    private val algId: AlgorithmIdentifier?

    constructor()
    {
        this.algId = null
    }

    internal constructor(algorithmIdentifier: AlgorithmIdentifier)
    {
        this.algId = algorithmIdentifier
    }

    override val algorithmIdentifier: AlgorithmIdentifier
        get() = {
            if (algId != null) {
                algId
            }
            else
            {
                throw IllegalStateException("spec not validated")
            }
        }.invoke()

    override fun validatedSpec(key: VerificationKey): CompositeSigSpec {

        if (algId == null) {
            if (key is BaseVerificationKey) {
                return CompositeSigSpec((key._pubKey as CompositePublicKey).algorithmIdentifier)
            }
            throw IllegalStateException("unknown key")
        }

        return this
    }

    override fun validatedSpec(key: SigningKey): CompositeSigSpec {


        
        if (algId == null) {
            if (key is BaseSigningKey) {
                return CompositeSigSpec((key._privKey as CompositePrivateKey).algorithmIdentifier)
            }
            throw IllegalStateException("unknown key")
        }

        return this
    }
}