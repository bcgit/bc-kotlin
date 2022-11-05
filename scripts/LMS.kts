import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERPrintableString
import org.bouncycastle.crypto.digests.SHAKEDigest
import org.bouncycastle.pqc.jcajce.interfaces.LMSPrivateKey
import org.bouncycastle.kcrypto.spec.asymmetric.*
import org.bouncycastle.kcrypto.cert.dsl.*
import org.bouncycastle.kcrypto.cms.dsl.certificateManagementMessage
import org.bouncycastle.kcrypto.dsl.*
import org.bouncycastle.kcrypto.SignatureCalculator
import org.bouncycastle.kcrypto.IndexedSignatureCalculator
import org.bouncycastle.kcrypto.SigningKey
import org.bouncycastle.kcrypto.VerificationKey
import org.bouncycastle.kutil.findBCProvider
import org.bouncycastle.kutil.writePEMObject
import org.bouncycastle.util.Pack
import org.bouncycastle.util.Strings
import java.io.OutputStreamWriter
import java.io.FileWriter
import java.lang.IllegalArgumentException
import java.math.BigInteger
import java.util.*

using(findBCProvider())

// Generate a serial number based on a constant seed, the public key and the current private key index.
// The predictability of the sequence will depend on knowledge of the seed - it needs to be a value independent
// of the private key and if "strict unpredictability" is reqyured should be protected the same way. Seed should be
// in the range of 16 to 32 bytes of random data.
fun generateSerialNumber(seed: ByteArray, pubKey: VerificationKey, sigCalc: SignatureCalculator<AlgorithmIdentifier>): BigInteger {
    if (seed.size < 16)
    {
        throw IllegalArgumentException("seed length must be at least 128 bits")
    }

    val idxSigCalc = sigCalc as IndexedSignatureCalculator<AlgorithmIdentifier>
    val xof = SHAKEDigest(256)

    val serial = ByteArray(20)
    val pubEnc = pubKey.encoding

    xof.update(seed, 0, seed.size)
    xof.update(Pack.longToBigEndian(idxSigCalc.index()), 0, 8)
    xof.update(pubEnc, 0, pubEnc.size)

    xof.doFinal(serial, 0, serial.size)

    // serial number 160 bits, positive, high byte not zero
    val top = (serial[0].toInt() and 0x7f).toByte()

    if (top.compareTo(0) == 0)
    {
        serial[0] = ((0x40 or (serial[1].toInt() xor serial[2].toInt())) and 0x7f).toByte();
    }
    else
    {
        serial[0] = top;
    }

    return BigInteger(serial)
}

var expDate = Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000)

var trustKp = signingKeyPair {
    lms {
        sigParameterSet = "lms-sha256-n32-h10"
        otsParameterSet = "sha256-n32-w2"
    }
}
var trustCertSeed = Strings.toByteArray("Non-random LMS certificate serial number seed")

val sigCalc = trustKp.signingKey.signatureCalculator(LMSSigSpec())

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
    serialNumber = generateSerialNumber(trustCertSeed, trustKp.verificationKey, sigCalc)
    issuer = trustName
    notAfter = expDate
    subject = trustName
    subjectPublicKey = trustKp.verificationKey

    extensions = trustExtensions

    signature {
        LMS using trustKp.signingKey
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

    serialNumber = generateSerialNumber(trustCertSeed, trustKp.verificationKey, sigCalc)

    notAfter = expDate
    subject = caName
    subjectPublicKey = caKp.verificationKey

    extensions = caExtensions

    signature {
        LMS using trustKp.signingKey
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

OutputStreamWriter(System.out).writePEMObject(trustKp.signingKey)
FileWriter("lmstrustpriv.pem").writePEMObject(trustKp.signingKey)
OutputStreamWriter(System.out).writePEMObject(trustCert)
FileWriter("lmstrustcert.pem").writePEMObject(trustCert)
// For a CMS file output with chain
//OutputStreamWriter(System.out).writePEMObject(certMgmt)

