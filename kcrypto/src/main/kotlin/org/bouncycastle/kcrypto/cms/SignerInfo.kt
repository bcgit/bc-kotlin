package org.bouncycastle.kcrypto.cms

import KCryptoServices
import org.bouncycastle.asn1.cms.AttributeTable
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cms.SignerId
import org.bouncycastle.cms.SignerInformation
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder
import org.bouncycastle.kcrypto.VerificationKey
import org.bouncycastle.kcrypto.cert.Certificate
import org.bouncycastle.kutil.Selector

import java.security.spec.X509EncodedKeySpec

class SignerInfo(internal val signerInf: SignerInformation) {
    val signerID: Selector<SignerInfo> get() = KSid(signerInf.sid)
    val certificateID: Selector<Certificate> get() = KSidCert(signerInf.sid)

    val signedAttributes: AttributeTable get() = signerInf.signedAttributes
    val unsignedAttributes: AttributeTable get() = signerInf.unsignedAttributes

    val encoded = signerInf.toASN1Structure().encoded

    fun signatureVerifiedBy(publicKey: VerificationKey): Boolean {

        var subPub = SubjectPublicKeyInfo.getInstance(publicKey.encoding)
        var sv = JcaSimpleSignerInfoVerifierBuilder().setProvider(KCryptoServices._provider).build(
            KCryptoServices.helper.createKeyFactory(subPub.algorithm.algorithm.id).generatePublic(
                X509EncodedKeySpec(publicKey.encoding)
            )
        )

        return signerInf.verify(sv)
    }

    fun signatureVerifiedBy(cert: Certificate): Boolean {
        var sv = JcaSimpleSignerInfoVerifierBuilder().setProvider(KCryptoServices._provider).build(cert._cert)

        return signerInf.verify(sv)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as SignerInfo

        if (encoded != null) {
            if (other.encoded == null) return false
            if (!encoded.contentEquals(other.encoded)) return false
        } else if (other.encoded != null) return false

        return true
    }

    override fun hashCode(): Int {
        return encoded?.contentHashCode() ?: 0
    }


}

private class KSid(private val sid: SignerId) : Selector<SignerInfo> {
    override fun matches(obj: SignerInfo): Boolean {
        return sid.match(obj.signerInf)
    }
}

internal class KSidCert(private val sid: SignerId) : Selector<Certificate> {
    override fun matches(obj: Certificate): Boolean {
        return sid.match(obj._cert)
    }
}