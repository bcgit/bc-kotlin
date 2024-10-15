import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.kcrypto.cert.dsl.*
import org.bouncycastle.kcrypto.dsl.*
import org.bouncycastle.kutil.findBCProvider
import org.bouncycastle.kutil.writePEMObject
import java.io.FileWriter
import java.io.OutputStreamWriter
import java.util.*


using(findBCProvider())

var subjectKp = signingKeyPair {
    mlDsa {
        parameterSet = "ml-dsa-44"
    }
}

val subjectName = x500Name {
    rdn(BCStyle.C, "AU")
    rdn(BCStyle.O, "The Legion of the Bouncy Castle")
    rdn(BCStyle.L, "Melbourne")
    rdn(BCStyle.CN, "Eric's Trust Anchor")
}

val pkcs10Req = pkcs10Request {
            subject = subjectName
            subjectKey = subjectKp.verificationKey
            attributes = attributes {
                attribute {
                    attrType = PKCSObjectIdentifiers.pkcs_9_at_extensionRequest
                    attrValue = extensions {
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
                }
            }

            signature {
                MLDSA using subjectKp.signingKey
            }
        }



OutputStreamWriter(System.out).writePEMObject(subjectKp.signingKey)
FileWriter("mldsa_priv.pem").writePEMObject(subjectKp.signingKey)

OutputStreamWriter(System.out).writePEMObject(pkcs10Req)
FileWriter("mldsa_pkcs10.pem").writePEMObject(pkcs10Req)

