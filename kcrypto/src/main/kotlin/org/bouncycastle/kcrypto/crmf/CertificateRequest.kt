package org.bouncycastle.kcrypto.crmf

import org.bouncycastle.asn1.crmf.CertReqMsg
import org.bouncycastle.cert.crmf.CertificateRequestMessage
import org.bouncycastle.kcrypto.Encodable

class CertificateRequest(private val certReqMsg: CertificateRequestMessage): Encodable {
    override val encoding: ByteArray
        get() = certReqMsg.getEncoded()

    fun toASN1Structure(): CertReqMsg = certReqMsg.toASN1Structure()
}