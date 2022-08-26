import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
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
    dilithium {
        parameterSet = "dilithium2"
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
    serialNumber = BigInteger.valueOf(7906244495041046713)
    issuer = trustName
    notAfter = expDate
    subject = trustName
    subjectPublicKey = trustKp.verificationKey

    extensions = trustExtensions

    signature {
        Dilithium using trustKp.signingKey
    }
}

var caKp = signingKeyPair {
    dilithium {
        parameterSet = "dilithium2"
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
        authorityKey = trustCert.subjectPublicKeyInfo
    })
}

var caCert = certificate {
    issuer = trustCert

    serialNumber = BigInteger.valueOf(7906244495041056713)

    notAfter = expDate
    subject = caName
    subjectPublicKey = caKp.verificationKey

    extensions = caExtensions

    signature {
        Dilithium using trustKp.signingKey
    }
}

var eeKp = signingKeyPair {
    dilithium {
        parameterSet = "dilithium2"
    }
}

var eeCert = certificate {

    serialNumber = BigInteger.valueOf(7906244495042346713)

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
        emailAltNameExtension {
            email = "feedback-crypto@bouncycastle.org"
        }
        subjectKeyIdentifierExtension {
            subjectKey = eeKp.verificationKey
        }
        authorityKeyIdentifierExtension {
            authorityKey = caCert.subjectPublicKeyInfo
        })
    }

    signature {
        Dilithium using caKp.signingKey
    }
}

var certMgmt = certificateManagementMessage {
    certificates = listOf(caCert, eeCert)
}

OutputStreamWriter(System.out).writePEMObject(eeKp.signingKey)
FileWriter("dilithiumpriv.pem").writePEMObject(eeKp.signingKey)

OutputStreamWriter(System.out).writePEMObject(eeCert)
FileWriter("dilithiumeecert.pem").writePEMObject(eeCert)
OutputStreamWriter(System.out).writePEMObject(caCert)
FileWriter("dilithiumcacert.pem").writePEMObject(caCert)
OutputStreamWriter(System.out).writePEMObject(trustCert)
FileWriter("dilithiumtrustcert.pem").writePEMObject(trustCert)
// For a CMS file output with chain
//OutputStreamWriter(System.out).writePEMObject(certMgmt)

