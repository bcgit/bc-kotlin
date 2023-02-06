package org.bouncycastle.kcrypto.cmp.dsl

import KCryptoServices
import org.bouncycastle.asn1.cmp.PKIBody
import org.bouncycastle.asn1.crmf.CertReqMsg
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder
import org.bouncycastle.cert.crmf.CertificateReqMessagesBuilder
import org.bouncycastle.cert.crmf.CertificateRequestMessage
import org.bouncycastle.kcrypto.*
import org.bouncycastle.kcrypto.cmp.ProtectedPKIMessage
import org.bouncycastle.kcrypto.crmf.CertificateRequest
import org.bouncycastle.kcrypto.dsl.BasePBKDFDetails
import org.bouncycastle.kcrypto.dsl.ScryptDetails
import org.bouncycastle.kcrypto.dsl.SignatureBlock
import org.bouncycastle.kcrypto.spec.kdf.PBKDF2Spec
import org.bouncycastle.kcrypto.spec.kdf.ScryptSpec
import org.bouncycastle.kcrypto.spec.kdf.findPrfAlgId
import org.bouncycastle.kcrypto.spec.symmetric.*
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.GenericKey
import org.bouncycastle.operator.MacCalculator
import org.bouncycastle.pkcs.jcajce.JcePBMac1CalculatorBuilder
import java.io.OutputStream

/**
 * DSL for block whose methods will return a calculator or a pkcs10RequestBuilder
 */
class MacBlock
{
    lateinit var mac: MacDetails

    val HMacSha224 = MacDetails(this, "HmacSHA224", 224, HMacSHA224GenSpec.authType)
    val HMacSha256 = MacDetails(this, "HmacSHA256", 256, HMacSHA256GenSpec.authType)
    val HMacSha384 = MacDetails(this, "HmacSHA384", 384, HMacSHA384GenSpec.authType)
    val HMacSha512 = MacDetails(this, "HmacSHA512", 512, HMacSHA512GenSpec.authType)

    fun SCRYPT(block: ScryptDetails.()-> Unit) = ScryptDetails().apply(block)

    fun PBKDF2(block: BasePBKDFDetails.()-> Unit) = BasePBKDFDetails().apply(block)

    fun build(): MacCalculator {
        val senderMacCalculator: MacCalculator
        val kdf = mac.pbe
        if (kdf == null) {
            senderMacCalculator = JcePBMac1CalculatorBuilder(mac.algName, mac.size).setProvider("BC").build(mac.passwd.toCharArray())
        } else {
            val rawKey = kdf.symmetricKey(mac.passwd.toCharArray()).encoding
            val baseCalc = KCryptoServices.authenticationKey(rawKey, mac.authType)
                                                    .macCalculator(HMacSpec(findPrfAlgId(mac.authType)))
            senderMacCalculator = MacCalc(baseCalc, rawKey)
        }
        return senderMacCalculator
    }
}

class MacCalc(val macCalculator: org.bouncycastle.kcrypto.MacCalculator<AlgorithmIdentifier>, val rawKey: ByteArray): MacCalculator {
    override fun getAlgorithmIdentifier(): AlgorithmIdentifier {
        return macCalculator.algorithmIdentifier
    }

    override fun getOutputStream(): OutputStream {
        return macCalculator.stream
    }

    override fun getMac(): ByteArray {
        return macCalculator.mac()
    }

    override fun getKey(): GenericKey {
        return GenericKey(macCalculator.algorithmIdentifier, rawKey)
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
class MacDetails(val parent: MacBlock, val algName: String, val size: Int, val authType: KeyType<AuthenticationKey>)
{
    lateinit var passwd: String

    var id: ID? = null
    var digest: Digest? = null
    var pbe: PBKDF? = null

    infix fun with(detail: Any): MacDetails {
        parent.mac = this;
        when (detail) {
            is ScryptDetails -> {
                val pbeSpec = ScryptSpec(detail.saltLength, detail.costParameter, detail.blockSize, detail.parallelization)
                pbe = KCryptoServices.pbkdf(pbeSpec, HMacGenSpec(this.algName, detail.keySize))
            }
            is BasePBKDFDetails -> {
                val pbeSpec = PBKDF2Spec(detail.saltLength, detail.iterationCount, authType)
                pbe = KCryptoServices.pbkdf(pbeSpec, HMacGenSpec(this.algName, detail.keySize))
            }
            else -> throw IllegalStateException("unknown detail type")
        }

        return this
    }

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
