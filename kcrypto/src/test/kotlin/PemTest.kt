import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.kcrypto.Digest
import org.bouncycastle.kcrypto.KeyPair
import org.bouncycastle.kcrypto.SigningKeyPair
import org.bouncycastle.kcrypto.cert.Certificate
import org.bouncycastle.kcrypto.cert.CertificateBuilder
import org.bouncycastle.kcrypto.pkcs.PKCS10RequestBuilder
import org.bouncycastle.kcrypto.spec.asymmetric.PKCS1SigSpec
import org.bouncycastle.kcrypto.spec.asymmetric.RSAGenSpec
import org.bouncycastle.kutil.readPEMObject
import org.bouncycastle.kutil.writePEMObject
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.io.File
import java.security.Security
import java.util.*

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PemTest {

    init {
        initProvider()
    }



    @Test
    fun `read write`() {

        val kp = KCryptoServices.signingKeyPair(RSAGenSpec(2048))

        val name = with(X500NameBuilder())
        {
            this.addRDN(BCStyle.C, "AU")
                    .addRDN(BCStyle.O, "The Legion of the Bouncy Castle")
                    .addRDN(BCStyle.L, "Melbourne")
                    .addRDN(BCStyle.CN, "Eric H. Echidna")
                    .addRDN(BCStyle.EmailAddress, "feedback-crypto@bouncycastle.org")
                    .build()
        }

        val expDate = Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000)
        val cert = with(CertificateBuilder(kp.signingKey, PKCS1SigSpec(Digest.SHA256), name))
        {
            this.setNotBefore(java.util.Date())
            this.setNotAfter(expDate)
            this.build(java.math.BigInteger.valueOf(7), kp.verificationKey)
        }


        val pkcs10Req = PKCS10RequestBuilder(kp, PKCS1SigSpec(Digest.SHA256), name).apply { }.build()

        val certReqFile = File.createTempFile("req", "pem")
        certReqFile.deleteOnExit()
        certReqFile.writePEMObject(pkcs10Req)


        val keyFile = File.createTempFile("key", "pem")
        keyFile.deleteOnExit()
        keyFile.writePEMObject(kp.signingKey)

        val certFile = File.createTempFile("cert", "pem")
        certFile.deleteOnExit()
        certFile.writePEMObject(cert)


        val readKp = SigningKeyPair(keyFile.readPEMObject<KeyPair?>() ?: throw IllegalStateException("no key pair"))
        val readCert = certFile.readPEMObject<Certificate?>() ?: throw java.lang.IllegalStateException("no cert")
        val readReq = certReqFile.readPEMObject<PKCS10CertificationRequest>()
                ?: throw java.lang.IllegalStateException("no req")


        assertArrayEquals(pkcs10Req.encoding, readReq.encoded)
        assertArrayEquals(kp.signingKey.encoding, readKp.signingKey.encoding)
        assertArrayEquals(kp.verificationKey.encoding, readKp.verificationKey.encoding)
        assertArrayEquals(cert.encoding, readCert.encoding)
    }


}