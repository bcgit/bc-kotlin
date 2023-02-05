package org.bouncycastle.kcrypto.cmp.dsl

import org.bouncycastle.asn1.cmp.PKIBody
import org.bouncycastle.asn1.crmf.CertReqMsg
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder
import org.bouncycastle.cert.crmf.CertificateReqMessagesBuilder
import org.bouncycastle.cert.crmf.CertificateRequestMessage
import org.bouncycastle.kcrypto.Digest
import org.bouncycastle.kcrypto.ID
import org.bouncycastle.kcrypto.SignatureCalculator
import org.bouncycastle.kcrypto.cmp.ProtectedPKIMessage
import org.bouncycastle.kcrypto.crmf.CertificateRequest
import org.bouncycastle.kcrypto.dsl.SignatureBlock
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.MacCalculator
import org.bouncycastle.pkcs.jcajce.JcePBMac1CalculatorBuilder
import java.io.OutputStream

/**
 * DSL for block whose methods will return a calculator or a pkcs10RequestBuilder
 */
class MacBlock
{
    lateinit var mac: MacDetails

    val HMacSha224 = MacDetails(this, "HmacSHA224", 224)
    val HMacSha256 = MacDetails(this, "HmacSHA256", 256)
    val HMacSha384 = MacDetails(this, "HmacSHA384", 384)
    val HMacSha512 = MacDetails(this, "HmacSHA512", 512)

    fun build(): MacCalculator {
        val senderMacCalculator =
                    JcePBMac1CalculatorBuilder(mac.algName, mac.size).setProvider("BC").build(mac.passwd.toCharArray())

        return senderMacCalculator
    }
}

class Signer(val signatureCalculator: SignatureCalculator<AlgorithmIdentifier>) : ContentSigner {
    override fun getAlgorithmIdentifier(): AlgorithmIdentifier {
        return signatureCalculator.algorithmIdentifier
    }

    override fun getOutputStream(): OutputStream {
        return signatureCalculator.stream
    }

    override fun getSignature(): ByteArray {
        return signatureCalculator.signature()
    }
}

/**
 * DSL for specifying the details of the Mac.
 */
class MacDetails(val parent: MacBlock, val algName: String, val size: Int)
{
    lateinit var passwd: String

    var id: ID? = null
    var digest: Digest? = null

    infix fun using(passwd: String): MacDetails {
        parent.mac = this;
        this.passwd = passwd

        return this
    }
}

class ProtPKIBody {
    lateinit var sender: GeneralName
    lateinit var recipient: GeneralName

    val messagesBody = RequestMessagesBody()

    val mac = MacBlock();

    var signature: SignatureBlock? = null;

    fun build(): ProtectedPKIMessage {
        val bld = ProtectedPKIMessageBuilder(sender, recipient)

        val msgsBldr = CertificateReqMessagesBuilder()

        val msgs = messagesBody.build()
        for (msg in msgs) {
            msgsBldr.addRequest(CertificateRequestMessage(msg))
        }
        // TODO: clearly incomplete
        bld.setBody(PKIBody.TYPE_INIT_REQ, msgsBldr.build())

        var sigCalc = signature?.signatureCalculator()
        if (sigCalc != null) {
            return ProtectedPKIMessage(bld.build(Signer(sigCalc)))
        } else {
            return ProtectedPKIMessage(bld.build(mac.build()))
        }
    }

    fun initReq(block: RequestMessagesBody.()-> Unit) = messagesBody.apply(block)

    fun mac(block: MacBlock.()-> Unit) = mac.apply(block)

    fun signature(block: SignatureBlock.()-> Unit) {
        val sb = SignatureBlock();
        sb.apply(block)
        signature = sb;
    }
}

class RequestMessagesBody {

    var requests: MutableList<CertReqMsg> = ArrayList()

    fun addRequest(request: CertificateRequest) {
        requests.add(request.toASN1Structure())
    }

    fun build(): List<CertReqMsg> {
        return requests
    }
}

/**
 * DSL for creating a CMP certificate request
 */
fun protectedPkiMessage(block: ProtPKIBody.()-> Unit): ProtectedPKIMessage = ProtPKIBody().apply(block).build()
