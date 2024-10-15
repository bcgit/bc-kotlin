import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.kcrypto.Digest
import org.bouncycastle.kcrypto.cert.dsl.*
import org.bouncycastle.kcrypto.dsl.ec
import org.bouncycastle.kcrypto.dsl.mlDsa
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

    var mlDsaRootKp = signingKeyPair {
        mlDsa {
            parameterSet = "ml-dsa-65"
        }
    }

    val mlDsaRootName = x500Name {
        rdn(BCStyle.C, "XX")
        rdn(BCStyle.O, "Royal Institute of Public Key Infrastructure")
        rdn(BCStyle.OU, "Post-Heffalump Research Department")
        rdn(BCStyle.CN, "MLDSA Root - G1")
    }

    var mlDsaRootCertExtensions = extensions {
        critical(basicConstraintsExtension {
            isCA = true
        })
        critical(keyUsageExtension {
            usage = KeyUsage.digitalSignature + KeyUsage.cRLSign + KeyUsage.keyCertSign
        })
        subjectKeyIdentifierExtension {
            subjectKey = mlDsaRootKp.verificationKey
        }
        authorityKeyIdentifierExtension {
            authorityKey = mlDsaRootKp.verificationKey
        }
        deltaCertificateDescriptorExtension {
            deltaCert = ecRootCert
        }
    }

    var mlDsaRootCert = certificate {
        issuer = mlDsaRootName

        serialNumber = calcSerialNumber(1)

        notAfter = expDate
        subject = mlDsaRootName
        subjectPublicKey = mlDsaRootKp.verificationKey

        extensions = mlDsaRootCertExtensions

        signature {
            MLDSA using mlDsaRootKp.signingKey
        }
    }
    
    var mlDsaEEKp = signingKeyPair {
        mlDsa {
            parameterSet = "ml-dsa-65"
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

    var mlDsaEECert = certificate {

        serialNumber = calcSerialNumber(2)

        issuer = mlDsaRootCert

        notAfter = expDate
        subject = eeName
        subjectPublicKey = mlDsaEEKp.verificationKey
        extensions = extensions {
            critical(basicConstraintsExtension {
                isCA = false
            })
            critical(keyUsageExtension {
                usage = KeyUsage.digitalSignature
            })
            subjectKeyIdentifierExtension {
                subjectKey = mlDsaEEKp.verificationKey
            }
            authorityKeyIdentifierExtension {
                authorityKey = mlDsaRootCert.subjectPublicKeyInfo
            }
        }

        signature {
            MLDSA using mlDsaRootKp.signingKey
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
                deltaCert = mlDsaEECert
            }
        }

        signature {
            ECDSA with sha512 using ecRootKp.signingKey
        }
    }
    
    OutputStreamWriter(FileOutputStream("ee_ec_priv.pem")).writePEMObject(ecEEKp.signingKey)

    OutputStreamWriter(FileOutputStream("ee_ec_cert.pem")).writePEMObject(ecEECert)

    OutputStreamWriter(FileOutputStream("ee_mldsa_priv.pem")).writePEMObject(mlDsaEEKp.signingKey)

    OutputStreamWriter(FileOutputStream("ee_mldsa_cert.pem")).writePEMObject(mlDsaEECert)

    OutputStreamWriter(FileOutputStream("ta_ec_priv.pem")).writePEMObject(ecRootKp.signingKey)

    OutputStreamWriter(FileOutputStream("ta_ec_cert.pem")).writePEMObject(ecRootCert)

    OutputStreamWriter(FileOutputStream("ta_mldsa_cert.pem")).writePEMObject(mlDsaRootCert)
}