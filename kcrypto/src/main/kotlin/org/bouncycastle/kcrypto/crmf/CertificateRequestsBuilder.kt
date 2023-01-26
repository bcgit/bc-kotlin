package org.bouncycastle.kcrypto.crmf

import org.bouncycastle.asn1.crmf.CertReqMessages
import org.bouncycastle.asn1.crmf.CertReqMsg
import org.bouncycastle.cert.crmf.CertificateReqMessages
import org.bouncycastle.cert.crmf.CertificateRequestMessage

class CertificateRequestsBuilder {
    var requests: MutableList<CertReqMsg> = ArrayList()
    fun addRequest(request: CertificateRequestMessage) {
        requests.add(request.toASN1Structure())
    }

    fun build(): CertificateReqMessages {
        val certificateReqMessages = CertificateReqMessages(CertReqMessages(requests.toTypedArray()))
        requests.clear()
        return certificateReqMessages
    }
}