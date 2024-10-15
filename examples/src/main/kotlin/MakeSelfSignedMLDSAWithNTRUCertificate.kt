import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.kcrypto.cert.dsl.*
import org.bouncycastle.kcrypto.dsl.*
import org.bouncycastle.kcrypto.pkcs.dsl.encryptedPrivateKey
import org.bouncycastle.kutil.findBCProvider
import org.bouncycastle.kutil.writePEMObject
import java.io.OutputStreamWriter
import java.math.BigInteger
import java.util.*

fun main() {

    using(findBCProvider())

    var sigKp = signingKeyPair {
        mlDsa {
            parameterSet = "ml-dsa-44"
        }
    }

    var encKp = encryptingKeyPair {
        ntru {
            parameterSet = "ntruhrss701"
        }
    }

    var expDate = Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000)

    var name = x500Name {
        rdn(BCStyle.C, "AU")
        rdn(BCStyle.O, "The Legion of the Bouncy Castle")
        rdn(BCStyle.L, "Melbourne")
        rdn(BCStyle.CN, "Eric H. Echidna")
        rdn(BCStyle.EmailAddress, "feedback-crypto@bouncycastle.org")
    }

    var cert = certificate {
        serialNumber = BigInteger.valueOf(1)
        issuer = name
        notAfter = expDate
        subject = name
        subjectPublicKey = sigKp.verificationKey

        extensions = extensions {
            subjectAltPublicKeyInfoExtension {
                publicKey = encKp.encryptionKey
            }
        }
        
        signature {
            MLDSA using sigKp.signingKey
        }
    }

    println("cert verifies " + cert.signatureVerifiedBy(cert))

    var encKey = encryptedPrivateKey {
        privateKey = sigKp.signingKey
        encryption {
            AESKWP using SCRYPT {
                saltLength = 20
                costParameter = 1048576
                blockSize = 8
                parallelization = 1
                keySize = 256
            } with "Test".toCharArray()
        }
    }

    OutputStreamWriter(System.out).writePEMObject(encKey)

    OutputStreamWriter(System.out).writePEMObject(cert)
}
