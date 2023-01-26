package org.bouncycastle.kcrypto.crmf.dsl

import org.bouncycastle.asn1.crmf.SubsequentMessage
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.kcrypto.PublicKey
import org.bouncycastle.kcrypto.crmf.CertificateRequest
import org.bouncycastle.kcrypto.crmf.CertificateRequestBuilder
import org.bouncycastle.kcrypto.dsl.SignatureBlock
import java.math.BigInteger


class POPBlock
{
    var raVerified = false
    var subsequentMessage: SubsequentMessage? = null
    
    private val signature = SignatureBlock()

    fun signature(block: SignatureBlock.()-> Unit) = signature.apply(block)
}

/**
 * DSL body for defining a CRMF cert request
 */
class CRMFBody
{
    lateinit var certReqID: BigInteger
    lateinit var subject: X500Name
    lateinit var publicKey: PublicKey

    private val pop = POPBlock()

    fun build(): CertificateRequest {

        var builder = CertificateRequestBuilder(certReqID)

        builder.setSubject(subject)

        if (pop.subsequentMessage != null) {
            builder.setProofOfPossessionSubsequentMessage(pop.subsequentMessage)
        }
        if (pop.raVerified) {
            builder.setProofOfPossessionRaVerified()
        }

        builder.setPublicKey(SubjectPublicKeyInfo.getInstance(publicKey.encoding))

        return builder.build()
    }

    fun proofOfPossession(block: POPBlock.()-> Unit) = pop.apply(block)
}

/**
 * DSL for creating a CRMF certificate request
 */
fun certificateRequest(block: CRMFBody.()-> Unit): CertificateRequest = CRMFBody().apply(block).build()



