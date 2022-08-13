import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.kcrypto.cert.dsl.*
import org.bouncycastle.kcrypto.dsl.encryptingKeyPair
import org.bouncycastle.kcrypto.dsl.rsa
import org.bouncycastle.kcrypto.dsl.signingKeyPair
import org.bouncycastle.kcrypto.dsl.using
import org.bouncycastle.kcrypto.pkcs.dsl.attribute
import org.bouncycastle.kcrypto.pkcs.dsl.attributes
import org.bouncycastle.kcrypto.pkcs.dsl.pkcs10Request
import org.bouncycastle.kutil.writePEMObject
import java.io.OutputStreamWriter

fun main() {

    using("BC")

    var kp = signingKeyPair {
        rsa {
            keySize = 2048
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
            extValue = BasicConstraints(true)
        })
        critical(extension {
            extOid = Extension.keyUsage
            extValue = KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign)
        })
        subjectKeyIdentifierExtension {
            subjectKey = kp.verificationKey
        }
    }

    var pkcs10 = pkcs10Request {
        subject = x500Name("CN=Test")
        subjectKey = kp.verificationKey
        attributes = attributes {
             attribute {
                 attrType = PKCSObjectIdentifiers.pkcs_9_at_extensionRequest
                 attrValue = extensions
             }
        }
        signature {
            PKCS1v1dot5 with sha256 using kp.signingKey
        }
    }

    OutputStreamWriter(System.out).writePEMObject(kp.signingKey)

    OutputStreamWriter(System.out).writePEMObject(pkcs10)
}
