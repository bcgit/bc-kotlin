import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.kcrypto.cert.dsl.*
import org.bouncycastle.kcrypto.cmp.dsl.protectedPkiMessage
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
            parameterSet = "ntruhrss701"
        }
    }

    var sigKp = signingKeyPair {
        mlDsa {
            parameterSet = "dilithium2"
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

    val sender = GeneralName(X500Name("CN=MLKEM Subject"))
    val recipient = GeneralName(X500Name("CN=MLDSA Issuer"))

    var macMessage = protectedPkiMessage {
        this.sender = sender
        this.recipient = recipient
        
        initReq {
             addRequest(crmfReq)
        }

        mac {
            HMacSha256 with SCRYPT {
                saltLength = 32
                keySize = 256
            } using "secret"
        }
    }

    var sigMessage = protectedPkiMessage {
        this.sender = sender
        this.recipient = recipient

        initReq {
             addRequest(crmfReq)
        }

        signature {
            MLDSA using sigKp.signingKey
        }
    }

    OutputStreamWriter(System.out).writePEMObject(kp.decryptionKey)

    OutputStreamWriter(System.out).writePEMObject(kp.encryptionKey)

    OutputStreamWriter(System.out).writePEMObject(macMessage)

    OutputStreamWriter(System.out).writePEMObject(sigMessage)
}
