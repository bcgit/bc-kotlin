package org.bouncycastle.kcrypto.spec

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.kcrypto.Digest
import org.bouncycastle.kcrypto.SigningKey
import org.bouncycastle.kcrypto.VerificationKey
import org.bouncycastle.kcrypto.spec.asymmetric.DSASigSpec
import org.bouncycastle.kcrypto.spec.asymmetric.ECDSASigSpec
import org.bouncycastle.kcrypto.spec.asymmetric.PKCS1SigSpec

interface SigAlgSpec : AlgSpec<AlgorithmIdentifier> {
    
    fun validatedSpec(key: SigningKey): SigAlgSpec

    fun validatedSpec(key: VerificationKey): SigAlgSpec

    companion object {
        fun createSpec(algId: AlgorithmIdentifier): SigAlgSpec {
            var sigAlgSpec = when (algId.algorithm) {
                NISTObjectIdentifiers.dsa_with_sha224 -> DSASigSpec(Digest.SHA224, algId)
                NISTObjectIdentifiers.dsa_with_sha256 -> DSASigSpec(Digest.SHA256, algId)
                NISTObjectIdentifiers.dsa_with_sha384 -> DSASigSpec(Digest.SHA384, algId)
                NISTObjectIdentifiers.dsa_with_sha512 -> DSASigSpec(Digest.SHA512, algId)
                PKCSObjectIdentifiers.sha1WithRSAEncryption -> PKCS1SigSpec(Digest.SHA1, algId)
                PKCSObjectIdentifiers.sha224WithRSAEncryption -> PKCS1SigSpec(Digest.SHA224, algId)
                PKCSObjectIdentifiers.sha256WithRSAEncryption -> PKCS1SigSpec(Digest.SHA256, algId)
                PKCSObjectIdentifiers.sha384WithRSAEncryption -> PKCS1SigSpec(Digest.SHA384, algId)
                PKCSObjectIdentifiers.sha512WithRSAEncryption -> PKCS1SigSpec(Digest.SHA512, algId)
                X9ObjectIdentifiers.ecdsa_with_SHA1 -> ECDSASigSpec(Digest.SHA1, algId)
                X9ObjectIdentifiers.ecdsa_with_SHA224 -> ECDSASigSpec(Digest.SHA224, algId)
                X9ObjectIdentifiers.ecdsa_with_SHA256 -> ECDSASigSpec(Digest.SHA256, algId)
                X9ObjectIdentifiers.ecdsa_with_SHA384 -> ECDSASigSpec(Digest.SHA384, algId)
                X9ObjectIdentifiers.ecdsa_with_SHA512 -> ECDSASigSpec(Digest.SHA512, algId)
                else -> throw IllegalArgumentException("unknown algorithm: " + algId.algorithm)
            }
            return sigAlgSpec
        }
    }
}