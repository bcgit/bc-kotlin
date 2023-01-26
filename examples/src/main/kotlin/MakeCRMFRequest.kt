import org.bouncycastle.asn1.cmp.PKIBody
import org.bouncycastle.asn1.crmf.SubsequentMessage
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.cmp.ProtectedPKIMessage
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.kcrypto.cert.dsl.*
import org.bouncycastle.kcrypto.cmp.dsl.protectedPkiMessage
import org.bouncycastle.kcrypto.crmf.CertificateRequest
import org.bouncycastle.kcrypto.crmf.dsl.certificateRequest
import org.bouncycastle.kcrypto.dsl.*
import org.bouncycastle.kutil.findBCProvider
import org.bouncycastle.kutil.writePEMObject
import java.io.OutputStreamWriter
import java.math.BigInteger

fun main() {

    using(findBCProvider())

    var kp = encryptingKeyPair {
        ntru {
            paramSet = "ntruhrss701"
        }
    }

    val name = x500Name {
        rdn(BCStyle.C, "AU")
        rdn(BCStyle.O, "The Legion of the Bouncy Castle")
        rdn(BCStyle.L, "Melbourne")
        rdn(BCStyle.CN, "Eric H. Echidna")
        rdn(BCStyle.EmailAddress, "feedback-crypto@bouncycastle.org")
    }

    val extensions = extensions {
        critical(extension {
            extOid = Extension.basicConstraints
            extValue = BasicConstraints(false)
        })
        critical(extension {
            extOid = Extension.keyUsage
            extValue = KeyUsage(KeyUsage.keyEncipherment)
        })
        subjectKeyIdentifierExtension {
            subjectKey = kp.encryptionKey
        }
    }

    var crmfReq = certificateRequest {
        certReqID = BigInteger.ONE
        subject = name
        publicKey = kp.encryptionKey
        proofOfPossession {
            raVerified = true
//            subsequentMessage = SubsequentMessage.encrCert
        }
    }

    val sender = GeneralName(X500Name("CN=Kyber Subject"))
    val recipient = GeneralName(X500Name("CN=Dilithium Issuer"))

    var message = protectedPkiMessage {
        this.sender = sender
        this.recipient = recipient
        
        initReq {
             addRequest(crmfReq)
        }

        mac {
            HMacSha256 using "secret"
        }
    }

    OutputStreamWriter(System.out).writePEMObject(kp.decryptionKey)

    OutputStreamWriter(System.out).writePEMObject(message)
}
