import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.kcrypto.Digest
import org.bouncycastle.kcrypto.cert.dsl.*
import org.bouncycastle.kcrypto.dsl.dilithium
import org.bouncycastle.kcrypto.dsl.ec
import org.bouncycastle.kcrypto.dsl.signingKeyPair
import org.bouncycastle.kcrypto.dsl.using
import org.bouncycastle.kutil.findBCProvider
import org.bouncycastle.kutil.writePEMObject
import java.io.FileOutputStream
import java.io.OutputStreamWriter
import java.math.BigInteger
import java.util.*
import kotlin.experimental.and

fun calcSerialNumber(order: Int): BigInteger
{
    var calc = Digest.SHA1.digestCalculator();

    calc.stream.write(order)
    calc.stream.write(BigInteger.valueOf(System.currentTimeMillis()).toByteArray())

    calc.stream.close()

    var digest = calc.digest()

    digest[0] = digest[0] and 0x7f   // make sure not negative

    return BigInteger(digest)
}

// Script showing use of the deltaCertificateDescriptor extension.
fun main() {

    using(findBCProvider())

    var expDate = Date(System.currentTimeMillis() + 10 * 365L * 24 * 60 * 60 * 1000)

    var ecRootKp = signingKeyPair {
        ec {
            curveName = "P-521"
        }
    }

    val ecRootName = x500Name {
        rdn(BCStyle.C, "XX")
        rdn(BCStyle.O, "Royal Institute of Public Key Infrastructure")
        rdn(BCStyle.OU, "Post-Heffalump Research Department")
        rdn(BCStyle.CN, "ECDSA Root - G1")
    }

    var ecRootCertExtensions = extensions {
        critical(basicConstraintsExtension {
            isCA = true
        })
        critical(keyUsageExtension {
            usage = KeyUsage.keyCertSign + KeyUsage.cRLSign
        })
        subjectKeyIdentifierExtension {
            subjectKey = ecRootKp.verificationKey
        }
        authorityKeyIdentifierExtension {
            authorityKey = ecRootKp.verificationKey
        }
    }

    var ecRootCert = certificate {
        serialNumber = calcSerialNumber(0)
        issuer = ecRootName
        notAfter = expDate
        subject = ecRootName
        subjectPublicKey = ecRootKp.verificationKey

        extensions = ecRootCertExtensions

        signature {
            ECDSA with sha512 using ecRootKp.signingKey
        }
    }

    var dilithiumRootKp = signingKeyPair {
        dilithium {
            parameterSet = "Dilithium3"
        }
    }

    val dilithiumRootName = x500Name {
        rdn(BCStyle.C, "XX")
        rdn(BCStyle.O, "Royal Institute of Public Key Infrastructure")
        rdn(BCStyle.OU, "Post-Heffalump Research Department")
        rdn(BCStyle.CN, "Dilithium Root - G1")
    }

    var dilithiumRootCertExtensions = extensions {
        critical(basicConstraintsExtension {
            isCA = true
        })
        critical(keyUsageExtension {
            usage = KeyUsage.digitalSignature + KeyUsage.cRLSign + KeyUsage.keyCertSign
        })
        subjectKeyIdentifierExtension {
            subjectKey = dilithiumRootKp.verificationKey
        }
        authorityKeyIdentifierExtension {
            authorityKey = dilithiumRootKp.verificationKey
        }
        deltaCertificateDescriptorExtension {
            deltaCert = ecRootCert
        }
    }

    var dilithiumRootCert = certificate {
        issuer = dilithiumRootName

        serialNumber = calcSerialNumber(1)

        notAfter = expDate
        subject = dilithiumRootName
        subjectPublicKey = dilithiumRootKp.verificationKey

        extensions = dilithiumRootCertExtensions

        signature {
            Dilithium using dilithiumRootKp.signingKey
        }
    }
    
    var dilithiumEEKp = signingKeyPair {
        dilithium {
            parameterSet = "Dilithium3"
        }
    }

    var ecEEKp = signingKeyPair {
        ec {
            curveName = "P-256"
        }
    }

    val eeName = x500Name {
        rdn(BCStyle.C, "XX")
        rdn(BCStyle.SURNAME, "Yamada")
        rdn(BCStyle.GIVENNAME, "Hanako")
    }

    var dilithiumEECert = certificate {

        serialNumber = calcSerialNumber(2)

        issuer = dilithiumRootCert

        notAfter = expDate
        subject = eeName
        subjectPublicKey = dilithiumEEKp.verificationKey
        extensions = extensions {
            critical(basicConstraintsExtension {
                isCA = false
            })
            critical(keyUsageExtension {
                usage = KeyUsage.digitalSignature
            })
            subjectKeyIdentifierExtension {
                subjectKey = dilithiumEEKp.verificationKey
            }
            authorityKeyIdentifierExtension {
                authorityKey = dilithiumRootCert.subjectPublicKeyInfo
            }
        }

        signature {
            Dilithium using dilithiumRootKp.signingKey
        }
    }

    var ecEECert = certificate {

        serialNumber = calcSerialNumber(3)

        issuer = ecRootCert

        notAfter = expDate
        subject = eeName
        subjectPublicKey = ecEEKp.verificationKey
        extensions = extensions {
            critical(basicConstraintsExtension {
                isCA = false
            })
            critical(keyUsageExtension {
                usage = KeyUsage.digitalSignature
            })
            subjectKeyIdentifierExtension {
                subjectKey = ecEEKp.verificationKey
            }
            authorityKeyIdentifierExtension {
                authorityKey = ecRootCert.subjectPublicKeyInfo
            }
            deltaCertificateDescriptorExtension {
                deltaCert = dilithiumEECert
            }
        }

        signature {
            ECDSA with sha512 using ecRootKp.signingKey
        }
    }
    
    OutputStreamWriter(FileOutputStream("ee_ec_priv.pem")).writePEMObject(ecEEKp.signingKey)

    OutputStreamWriter(FileOutputStream("ee_ec_cert.pem")).writePEMObject(ecEECert)

    OutputStreamWriter(FileOutputStream("ee_dil_priv.pem")).writePEMObject(dilithiumEEKp.signingKey)

    OutputStreamWriter(FileOutputStream("ee_dil_cert.pem")).writePEMObject(dilithiumEECert)

    OutputStreamWriter(FileOutputStream("ta_ec_priv.pem")).writePEMObject(ecRootKp.signingKey)

    OutputStreamWriter(FileOutputStream("ta_ec_cert.pem")).writePEMObject(ecRootCert)

    OutputStreamWriter(FileOutputStream("ta_dil_cert.pem")).writePEMObject(dilithiumRootCert)
}