import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.kcrypto.cert.dsl.*
import org.bouncycastle.kcrypto.cms.dsl.certificateManagementMessage
import org.bouncycastle.kcrypto.dsl.rsa
import org.bouncycastle.kcrypto.dsl.signingKeyPair
import org.bouncycastle.kcrypto.dsl.using
import org.bouncycastle.kutil.findBCProvider
import org.bouncycastle.kutil.writePEMObject
import java.io.OutputStreamWriter
import java.math.BigInteger
import java.util.*

fun main() {

    using(findBCProvider())

    var expDate = Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000)

    var trustKp = signingKeyPair {
        rsa {
            keySize = 2048
        }
    }

    val trustName = x500Name {
        rdn(BCStyle.C, "AU")
        rdn(BCStyle.O, "The Legion of the Bouncy Castle")
        rdn(BCStyle.L, "Melbourne")
        rdn(BCStyle.CN, "Eric's Trust Anchor")
    }

    var trustCert = certificate {
        serialNumber = BigInteger.valueOf(1)
        issuer = trustName
        notAfter = expDate
        subject = trustName
        subjectPublicKey = trustKp.verificationKey

        signature {
            PKCS1v1dot5 with sha256 using trustKp.signingKey
        }
    }

    var caKp = signingKeyPair {
        rsa {
            keySize = 2048
        }
    }

    val caName = x500Name {
        rdn(BCStyle.C, "AU")
        rdn(BCStyle.O, "The Legion of the Bouncy Castle")
        rdn(BCStyle.L, "Melbourne")
        rdn(BCStyle.CN, "Eric's CA")
    }

    var caExtensions = extensions {
        critical(extension {
            extOid = Extension.basicConstraints
            extValue = BasicConstraints(true)
        })
        critical(extension {
            extOid = Extension.keyUsage
            extValue = KeyUsage(KeyUsage.cRLSign or KeyUsage.keyCertSign)
        })
        critical(subjectKeyIdentifierExtension {
            subjectKey = caKp.verificationKey
        })
        critical(authorityKeyIdentifierExtension {
            authorityKey = trustCert
        })
    }

    var caCert = certificate {
        issuer = trustCert

        serialNumber = BigInteger.valueOf(1)

        notAfter = expDate
        subject = caName
        subjectPublicKey = caKp.verificationKey

        extensions = caExtensions

        signature {
            PKCS1v1dot5 with sha256 using trustKp.signingKey
        }
    }

    var eeKp = signingKeyPair {
        rsa {
            keySize = 2048
        }
    }

    var eeCert = certificate {

        serialNumber = BigInteger.valueOf(1)

        issuer = caCert

        notAfter = expDate
        subject = x500Name {
            rdn(BCStyle.C, "AU")
            rdn(BCStyle.O, "The Legion of the Bouncy Castle")
            rdn(BCStyle.L, "Melbourne")
            rdn(BCStyle.CN, "Eric H. Echidna")
            rdn(BCStyle.EmailAddress, "feedback-crypto@bouncycastle.org")
        }
        subjectPublicKey = eeKp.verificationKey
        extensions = extensions {
            critical(basicConstraintsExtension {
                isCA = false
            })
            subjectKeyIdentifierExtension {
                subjectKey = eeKp.verificationKey
            }
            critical(authorityKeyIdentifierExtension {
                authorityKey = caCert
            })
        }

        signature {
            PKCS1v1dot5 with sha256 using trustKp.signingKey
        }
    }

    var certMgmt = certificateManagementMessage {
        certificates = listOf(caCert, eeCert)
    }

    OutputStreamWriter(System.out).writePEMObject(eeKp.signingKey)

    OutputStreamWriter(System.out).writePEMObject(eeCert)

    OutputStreamWriter(System.out).writePEMObject(certMgmt)
}