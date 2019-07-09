import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.kcrypto.Digest
import org.bouncycastle.kcrypto.cert.CertificateBuilder
import org.bouncycastle.kcrypto.cert.dsl.authorityKeyIdentifierExtension
import org.bouncycastle.kcrypto.cert.dsl.extension
import org.bouncycastle.kcrypto.cert.dsl.extensions
import org.bouncycastle.kcrypto.cert.dsl.subjectKeyIdentifierExtension
import org.bouncycastle.kcrypto.pkcs.dsl.encryptedPrivateKey
import org.bouncycastle.kcrypto.spec.asymmetric.PKCS1SigSpec
import org.bouncycastle.kcrypto.spec.asymmetric.RSAGenSpec
import org.bouncycastle.kutil.writePEMObject
import java.io.OutputStreamWriter
import java.math.BigInteger
import java.util.*

fun main() {

    KCryptoServices.setProvider(findBCProvider())

    var kp = KCryptoServices.signingKeyPair(RSAGenSpec(2048))

    val name = with(X500NameBuilder())
    {
        this.addRDN(BCStyle.C, "AU")
                .addRDN(BCStyle.O, "The Legion of the Bouncy Castle")
                .addRDN(BCStyle.L, "Melbourne")
                .addRDN(BCStyle.CN, "Eric H. Echidna")
                .addRDN(BCStyle.EmailAddress, "feedback-crypto@bouncycastle.org")
                .build()
    }

    var exts = extensions {
        extension {
            extOid = Extension.basicConstraints
            extValue = BasicConstraints(false)
        }
        subjectKeyIdentifierExtension {
            subjectKey = kp.verificationKey
        }
        authorityKeyIdentifierExtension {
            authorityKey = kp.verificationKey
        }
    }

    var expDate = Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000)
    var cert = with(CertificateBuilder(kp.signingKey, PKCS1SigSpec(Digest.SHA256), name))
    {
        this.setNotBefore(Date())
                .setNotAfter(expDate)
                .setExtensions(exts)
                .build(BigInteger.valueOf(8), kp.verificationKey)
    }

    var encKey = encryptedPrivateKey {
        privateKey = kp.signingKey
        encryption {
            AESGCM tagSize 128 using PBKDF2 {
                saltLength = 20
                iterationCount = 4096
                prf = sha256
            } with "Test".toCharArray()
        }
    }

    OutputStreamWriter(System.out).writePEMObject(encKey)

    OutputStreamWriter(System.out).writePEMObject(cert)
}