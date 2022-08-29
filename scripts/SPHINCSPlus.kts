import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERPrintableString
import org.bouncycastle.kcrypto.cert.dsl.*
import org.bouncycastle.kcrypto.cms.dsl.certificateManagementMessage
import org.bouncycastle.kcrypto.dsl.*
import org.bouncycastle.kutil.findBCProvider
import org.bouncycastle.kutil.writePEMObject
import java.io.OutputStreamWriter
import java.io.FileWriter
import java.math.BigInteger
import java.util.*


using(findBCProvider())

var expDate = Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000)

var trustKp = signingKeyPair {
    sphincsPlus {
        parameterSet = "shake-256f-robust"
    }
}

val trustName = x500Name {
    rdn(BCStyle.C, "AU")
    rdn(BCStyle.O, "The Legion of the Bouncy Castle")
    rdn(BCStyle.L, "Melbourne")
    rdn(BCStyle.CN, "Eric's Trust Anchor")
}

var trustExtensions = extensions {
    critical(extension {
        extOid = Extension.basicConstraints
        extValue = BasicConstraints(true)
    })
    critical(extension {
        extOid = Extension.keyUsage
        extValue = KeyUsage(KeyUsage.cRLSign or KeyUsage.keyCertSign)
    })
    critical(subjectKeyIdentifierExtension {
        subjectKey = trustKp.verificationKey
    })
    critical(authorityKeyIdentifierExtension {
        authorityKey = trustKp.verificationKey
    })
}

var trustCert = certificate {
    serialNumber = BigInteger.valueOf(7906244495041046712)
    issuer = trustName
    notAfter = expDate
    subject = trustName
    subjectPublicKey = trustKp.verificationKey

    extensions = trustExtensions

    signature {
        SPHINCSPlus using trustKp.signingKey
    }
}

var caKp = signingKeyPair {
    sphincsPlus {
        parameterSet = "shake-256f-robust"
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
    issuerAltNameExtension {
        rfc822Name("feedback-crypto@bouncycastle.org")
        email("feedback-crypto@bouncycastle.org")
        uniformResourceIdentifier("https://www.bouncycastle.org/1")
        uri("https://www.bouncycastle.org/2")
        url("https://www.bouncycastle.org/3")
        directoryName("CN=Eric's CA,L=Melbourne,O=The Legion of the Bouncy Castle,C=AU")
        generalName(GeneralName.otherName, DERSequence(DERPrintableString("Other")))
    }    
    critical(subjectKeyIdentifierExtension {
        subjectKey = caKp.verificationKey
    })
    critical(authorityKeyIdentifierExtension {
        authorityKey = trustCert.subjectPublicKeyInfo
    })
}

var caCert = certificate {
    issuer = trustCert

    serialNumber = BigInteger.valueOf(7906244495041056712)

    notAfter = expDate
    subject = caName
    subjectPublicKey = caKp.verificationKey

    extensions = caExtensions

    signature {
        SPHINCSPlus using trustKp.signingKey
    }
}

var eeKp = signingKeyPair {
    sphincsPlus {
        parameterSet = "shake-256f-robust"
    }
}

var eeCert = certificate {

    serialNumber = BigInteger.valueOf(7906244495042346712)

    issuer = caCert

    notAfter = expDate
    subject = x500Name {
        rdn(BCStyle.C, "AU")
        rdn(BCStyle.O, "The Legion of the Bouncy Castle")
        rdn(BCStyle.L, "Melbourne")
        rdn(BCStyle.CN, "Eric H. Echidna")
    }
    subjectPublicKey = eeKp.verificationKey
    extensions = extensions {
        critical(basicConstraintsExtension {
            isCA = false
        })
        subjectAltNameExtension {
            rfc822Name("feedback-crypto@bouncycastle.org")
            email("feedback-crypto@bouncycastle.org")
            dNSName("bouncycastle.org")
            iPAddress("10.9.7.6")
            registeredID("1.2.3") // OID
            directoryName("CN=Eric H. Echidna,L=Melbourne,O=The Legion of the Bouncy Castle,C=AU")
        }
        subjectKeyIdentifierExtension {
            subjectKey = eeKp.verificationKey
        }
        critical(authorityKeyIdentifierExtension {
            authorityKey = caCert.subjectPublicKeyInfo
        })
    }

    signature {
        SPHINCSPlus using caKp.signingKey
    }
}

var certMgmt = certificateManagementMessage {
    certificates = listOf(caCert, eeCert)
}

OutputStreamWriter(System.out).writePEMObject(eeKp.signingKey)
FileWriter("sphincspluspriv.pem").writePEMObject(eeKp.signingKey)

OutputStreamWriter(System.out).writePEMObject(eeCert)
FileWriter("sphincspluseecert.pem").writePEMObject(eeCert)
OutputStreamWriter(System.out).writePEMObject(caCert)
FileWriter("sphincspluscacert.pem").writePEMObject(caCert)
OutputStreamWriter(System.out).writePEMObject(trustCert)
FileWriter("sphincsplustrustcert.pem").writePEMObject(trustCert)
// For a CMS file output with chain
//OutputStreamWriter(System.out).writePEMObject(certMgmt)

