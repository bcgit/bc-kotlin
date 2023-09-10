package org.bouncycastle.kcrypto.spec

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.bc.BCObjectIdentifiers
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.kcrypto.Digest
import org.bouncycastle.kcrypto.ID
import org.bouncycastle.kcrypto.SigningKey
import org.bouncycastle.kcrypto.VerificationKey
import org.bouncycastle.kcrypto.spec.asymmetric.*

// these are only in 1.0.2
private val id_Ed25519 = ASN1ObjectIdentifier("1.3.101").branch("112").intern()
private val id_Ed448 = ASN1ObjectIdentifier("1.3.101").branch("113").intern()
private val falcon_512 = ASN1ObjectIdentifier("1.3.9999.3.1") // falcon.branch("1");
private val falcon_1024 = ASN1ObjectIdentifier("1.3.9999.3.4") // falcon.branch("2");

interface SigAlgSpec : AlgSpec<AlgorithmIdentifier> {
    
    fun validatedSpec(key: SigningKey): SigAlgSpec

    fun validatedSpec(key: VerificationKey): SigAlgSpec

    companion object {
        fun createSpec(algId: AlgorithmIdentifier, id: ID?): SigAlgSpec {
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
                id_Ed25519 -> EdDSASigSpec(algId)
                id_Ed448 -> EdDSASigSpec(algId)
                falcon_512 -> FalconSigSpec(algId)
                falcon_1024 -> FalconSigSpec(algId)
                dilithium2 -> DilithiumSigSpec(algId)
                dilithium3 -> DilithiumSigSpec(algId)
                dilithium5 -> DilithiumSigSpec(algId)
                BCObjectIdentifiers.sphincsPlus_sha2_128f -> SPHINCSPlusSigSpec(algId)
                BCObjectIdentifiers.sphincsPlus_sha2_128s -> SPHINCSPlusSigSpec(algId)
                BCObjectIdentifiers.sphincsPlus_sha2_192f -> SPHINCSPlusSigSpec(algId)
                BCObjectIdentifiers.sphincsPlus_sha2_192s -> SPHINCSPlusSigSpec(algId)
                BCObjectIdentifiers.sphincsPlus_sha2_256f -> SPHINCSPlusSigSpec(algId)
                BCObjectIdentifiers.sphincsPlus_sha2_256s -> SPHINCSPlusSigSpec(algId)
                BCObjectIdentifiers.sphincsPlus_shake_128f -> SPHINCSPlusSigSpec(algId)
                BCObjectIdentifiers.sphincsPlus_shake_128s -> SPHINCSPlusSigSpec(algId)
                BCObjectIdentifiers.sphincsPlus_shake_192f -> SPHINCSPlusSigSpec(algId)
                BCObjectIdentifiers.sphincsPlus_shake_192s -> SPHINCSPlusSigSpec(algId)
                BCObjectIdentifiers.sphincsPlus_shake_256f -> SPHINCSPlusSigSpec(algId)
                BCObjectIdentifiers.sphincsPlus_shake_256s -> SPHINCSPlusSigSpec(algId)
                // SM3withSM2
                ASN1ObjectIdentifier("1.2.156.10197.1.501") -> SM2SigSpec(Digest.SM3, id, algId)
                else -> throw IllegalArgumentException("unknown algorithm: " + algId.algorithm)
            }
            return sigAlgSpec
        }
    }
}