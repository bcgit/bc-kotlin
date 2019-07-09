package org.bouncycastle.kcrypto.spec

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.spec.symmetric.CCMSpec
import org.bouncycastle.kcrypto.spec.symmetric.GCMSpec
import org.bouncycastle.kcrypto.spec.symmetric.KWPSpec

internal fun createAlgOID(keySize: Int, algSpec: AlgSpec<AlgorithmIdentifier>): ASN1ObjectIdentifier {
    var algOid: ASN1ObjectIdentifier;

    when (algSpec) {
        is GCMSpec -> when (keySize) {
            128 -> algOid = NISTObjectIdentifiers.id_aes128_GCM
            192 -> algOid = NISTObjectIdentifiers.id_aes192_GCM
            256 -> algOid = NISTObjectIdentifiers.id_aes256_GCM
            else -> {
                throw IllegalStateException("unknown AES key size")
            }
        }
        is CCMSpec -> when (keySize) {
            128 -> algOid = NISTObjectIdentifiers.id_aes128_CCM
            192 -> algOid = NISTObjectIdentifiers.id_aes192_CCM
            256 -> algOid = NISTObjectIdentifiers.id_aes256_CCM
            else -> {
                throw IllegalStateException("unknown AES key size")
            }
        }
        is KWPSpec -> when (keySize) {
            128 -> algOid = NISTObjectIdentifiers.id_aes128_wrap_pad
            192 -> algOid = NISTObjectIdentifiers.id_aes192_wrap_pad
            256 -> algOid = NISTObjectIdentifiers.id_aes256_wrap_pad
            else -> {
                throw IllegalStateException("unknown AES key size")
            }
        }
        else -> {
            throw IllegalStateException("unknown AlgSpec")
        }
    }

    return algOid
}