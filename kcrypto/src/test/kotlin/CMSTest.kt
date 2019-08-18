import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.Time
import org.bouncycastle.kcrypto.Digest
import org.bouncycastle.kcrypto.SigningKeyPair
import org.bouncycastle.kcrypto.cert.CRL
import org.bouncycastle.kcrypto.cert.Certificate
import org.bouncycastle.kcrypto.cert.CertificateBuilder
import org.bouncycastle.kcrypto.cert.V2CRLBuilder
import org.bouncycastle.kcrypto.cms.*
import org.bouncycastle.kcrypto.spec.asymmetric.PKCS1SigSpec
import org.bouncycastle.kcrypto.spec.asymmetric.RSAGenSpec
import org.bouncycastle.kutil.CollectionStore
import org.bouncycastle.util.encoders.Base64
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.MessageDigest
import java.util.*


@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CMSTest {

    init {
        initProvider()
    }


    val TestMessage = "Hello World!"
    private val signDN: X500Name
    private val signKP: SigningKeyPair
    private val signCert: Certificate

    private val origDN: X500Name
    private val origKP: SigningKeyPair
    private val origCert: Certificate

    private val signCrl: CRL
    private val origCrl: CRL


    init {

        initProvider()


        signDN = with(X500NameBuilder())
        {
            this.addRDN(BCStyle.C, "AU")
                .addRDN(BCStyle.O, "Bouncy Castle")
                .build()
        }


        signKP = KCryptoServices.signingKeyPair(RSAGenSpec(1024))

        signCert = with(CertificateBuilder(signKP.signingKey, PKCS1SigSpec(Digest.SHA256), signDN))
        {
            this.setNotBefore(Date())
                .setNotAfter(Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)))
                .build(BigInteger.valueOf(7), signKP.verificationKey)
        }


        origDN = with(X500NameBuilder())
        {
            this.addRDN(BCStyle.CN, "Bob")
                .addRDN(BCStyle.OU, "Sales")
                .addRDN(BCStyle.C, "AU")
                .addRDN(BCStyle.O, "Bouncy Castle")
                .build()
        }
        origKP = KCryptoServices.signingKeyPair(RSAGenSpec(1024))
        origCert = with(CertificateBuilder(signKP.signingKey, PKCS1SigSpec(Digest.SHA256), signDN))
        {
            this.setNotBefore(Date())
                .setNotAfter(Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)))
                .build(BigInteger.valueOf(7), origDN, origKP.verificationKey)
        }






        signCrl = V2CRLBuilder(signCert, Time(Date())).build(
            signKP.signingKey,
                PKCS1SigSpec(Digest.SHA256)
        );
        origCrl = V2CRLBuilder(origCert, Time(Date())).build(
            origKP.signingKey,
                PKCS1SigSpec(Digest.SHA256)
        );


    }

    val encapSigData = Base64.decode(
        "MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEH"
                + "AaCAJIAEDEhlbGxvIFdvcmxkIQAAAAAAAKCCBGIwggINMIIBdqADAgECAgEF"
                + "MA0GCSqGSIb3DQEBBAUAMCUxFjAUBgNVBAoTDUJvdW5jeSBDYXN0bGUxCzAJ"
                + "BgNVBAYTAkFVMB4XDTA1MDgwNzA2MjU1OVoXDTA1MTExNTA2MjU1OVowJTEW"
                + "MBQGA1UEChMNQm91bmN5IENhc3RsZTELMAkGA1UEBhMCQVUwgZ8wDQYJKoZI"
                + "hvcNAQEBBQADgY0AMIGJAoGBAI1fZGgH9wgC3QiK6yluH6DlLDkXkxYYL+Qf"
                + "nVRszJVYl0LIxZdpb7WEbVpO8fwtEgFtoDsOdxyqh3dTBv+L7NVD/v46kdPt"
                + "xVkSNHRbutJVY8Xn4/TC/CDngqtbpbniMO8n0GiB6vs94gBT20M34j96O2IF"
                + "73feNHP+x8PkJ+dNAgMBAAGjTTBLMB0GA1UdDgQWBBQ3XUfEE6+D+t+LIJgK"
                + "ESSUE58eyzAfBgNVHSMEGDAWgBQ3XUfEE6+D+t+LIJgKESSUE58eyzAJBgNV"
                + "HRMEAjAAMA0GCSqGSIb3DQEBBAUAA4GBAFK3r1stYOeXYJOlOyNGDTWEhZ+a"
                + "OYdFeFaS6c+InjotHuFLAy+QsS8PslE48zYNFEqYygGfLhZDLlSnJ/LAUTqF"
                + "01vlp+Bgn/JYiJazwi5WiiOTf7Th6eNjHFKXS3hfSGPNPIOjvicAp3ce3ehs"
                + "uK0MxgLAaxievzhFfJcGSUMDMIICTTCCAbagAwIBAgIBBzANBgkqhkiG9w0B"
                + "AQQFADAlMRYwFAYDVQQKEw1Cb3VuY3kgQ2FzdGxlMQswCQYDVQQGEwJBVTAe"
                + "Fw0wNTA4MDcwNjI1NTlaFw0wNTExMTUwNjI1NTlaMGUxGDAWBgNVBAMTD0Vy"
                + "aWMgSC4gRWNoaWRuYTEkMCIGCSqGSIb3DQEJARYVZXJpY0Bib3VuY3ljYXN0"
                + "bGUub3JnMRYwFAYDVQQKEw1Cb3VuY3kgQ2FzdGxlMQswCQYDVQQGEwJBVTCB"
                + "nzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAgHCJyfwV6/V3kqSu2SOU2E/K"
                + "I+N0XohCMUaxPLLNtNBZ3ijxwaV6JGFz7siTgZD/OGfzir/eZimkt+L1iXQn"
                + "OAB+ZChivKvHtX+dFFC7Vq+E4Uy0Ftqc/wrGxE6DHb5BR0hprKH8wlDS8wSP"
                + "zxovgk4nH0ffUZOoDSuUgjh3gG8CAwEAAaNNMEswHQYDVR0OBBYEFLfY/4EG"
                + "mYrvJa7Cky+K9BJ7YmERMB8GA1UdIwQYMBaAFDddR8QTr4P634sgmAoRJJQT"
                + "nx7LMAkGA1UdEwQCMAAwDQYJKoZIhvcNAQEEBQADgYEADIOmpMd6UHdMjkyc"
                + "mIE1yiwfClCsGhCK9FigTg6U1G2FmkBwJIMWBlkeH15uvepsAncsgK+Cn3Zr"
                + "dZMb022mwtTJDtcaOM+SNeuCnjdowZ4i71Hf68siPm6sMlZkhz49rA0Yidoo"
                + "WuzYOO+dggzwDsMldSsvsDo/ARyCGOulDOAxggEvMIIBKwIBATAqMCUxFjAU"
                + "BgNVBAoTDUJvdW5jeSBDYXN0bGUxCzAJBgNVBAYTAkFVAgEHMAkGBSsOAwIa"
                + "BQCgXTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEP"
                + "Fw0wNTA4MDcwNjI1NTlaMCMGCSqGSIb3DQEJBDEWBBQu973mCM5UBOl9XwQv"
                + "lfifHCMocTANBgkqhkiG9w0BAQEFAASBgGxnBl2qozYKLgZ0ygqSFgWcRGl1"
                + "LgNuE587LtO+EKkgoc3aFqEdjXlAyP8K7naRsvWnFrsB6pUpnrgI9Z8ZSKv8"
                + "98IlpsSSJ0jBlEb4gzzavwcBpYbr2ryOtDcF+kYmKIpScglyyoLzm+KPXOoT"
                + "n7MsJMoKN3Kd2Vzh6s10PFgeAAAAAAAA"
    )


    private fun verifySignaturesParser(sp: SignedDataParser, contentDigest: ByteArray? = null) {

        val certStore = sp.certificates
        val crlStore = sp.crls
        val signers = sp.signerInfos

        val digestIDs = HashSet<AlgorithmIdentifier>().apply {
            addAll(sp.digestAlgorithms)
        }

        assertTrue(digestIDs.size > 0)

        val c = signers.iterator()


        c.forEach {
            val first = certStore.matches(it.certificateID).first()


            assertTrue(it.signatureVerifiedBy(first))
            digestIDs.remove(it.signerInf.digestAlgorithmID)


            if (contentDigest != null) {
                assertTrue(MessageDigest.isEqual(contentDigest, it.signerInf.contentDigest))
            }
        }

        assertEquals(0, digestIDs.size)
        assertEquals(certStore.size, sp.certificates.size)
        assertEquals(crlStore.size, sp.crls.size)

    }


    private fun verifySignatures(sp: SignedData, contentDigest: ByteArray? = null) {

        val certStore = sp.certificates
        val crlStore = sp.crls
        val signers = sp.signerInfos

        val digestIDs = HashSet<AlgorithmIdentifier>().apply {
            addAll(sp.digestAlgorithms)
        }

        assertTrue(digestIDs.size > 0)

        val c = signers.iterator()


        c.forEach {
            val first = certStore.matches(it.certificateID).first()

            assertTrue(it.signatureVerifiedBy(first))
            digestIDs.remove(it.signerInf.digestAlgorithmID)


            if (contentDigest != null) {
                assertTrue(MessageDigest.isEqual(contentDigest, it.signerInf.contentDigest))
            }
        }

        assertEquals(0, digestIDs.size)
        assertEquals(certStore.size, sp.certificates.size)
        assertEquals(crlStore.size, sp.crls.size)

    }


    private fun checkSigParseable(sig: ByteArray) {
        val sp = SignedDataParser(sig)
        val sc = sp.signedContent
        sc?.drain()
        sp.certificates
        sp.crls
        sp.signerInfos
    }


    private fun verifyEncodedData(bOut: ByteArrayOutputStream) {
        val sp = SignedDataParser(ByteArrayInputStream(bOut.toByteArray()))
        sp.signedContent?.drain()
        verifySignaturesParser(sp)
    }


    @Test
    fun testSha1EncapsulatedSignature() {
        val sdp = SignedDataParser(encapSigData)
        sdp.signedContent?.drain()
        verifySignaturesParser(sdp)

    }

    @Test
    fun testSHA256WithRSANoAttributes() {
        val typedContent = TypedByteArray(TestMessage.toByteArray())

        val certList = listOf(origCert, signCert)
        val certs = CollectionStore<Certificate>(certList)

        val infoGen = SignerInfoGenerator(origKP.signingKey, PKCS1SigSpec(Digest.SHA256), certList[0]).apply {
            withDirectSignature(true)
        }

        val signedData = SignedDataBuilder().apply {
            addCertificates(certs)
            addSignerInfoGenerator(infoGen)
        }.build(typedContent, false)


        val smsg = SignedData(signedData, typedContent)

        val digest = Digest.SHA256.digestCalculator().apply { stream.use { it.write(typedContent.content) } }.digest()


        verifySignatures(smsg, digest)
    }


    @Test
    fun testSHA256WithRSA() {

        val typedContent = TypedByteArray(TestMessage.toByteArray())
        val certList = listOf(origCert, signCert)
        val crlList = listOf(signCrl, origCrl)

        val certs = CollectionStore(certList)
        val crls = CollectionStore(crlList)

        val infoGen = SignerInfoGenerator(origKP.signingKey, PKCS1SigSpec(Digest.SHA256), certList[0])

        val signedData = SignedDataBuilder().apply {
            addCertificates(certs)
            addSignerInfoGenerator(infoGen)
            addCRLs(crls)
        }.build(TypedByteArray(TestMessage.toByteArray()), false)


        checkSigParseable(signedData.encoding)


        val sdp = SignedDataParser(signedData, typedContent.typedStream())
        sdp.signedContent?.drain()


        //
        // compute expected content digest.
        //
        val digest = Digest.SHA256.digestCalculator().apply { stream.use { it.write(typedContent.content) } }.digest()
        verifySignaturesParser(sdp, digest)


        //
        // type using existing signer
        //

        val bos = ByteArrayOutputStream()

        SignedDataStreamBuilder().apply {
            addSigners(sdp.signerInfos)
            addCertificates(sdp.certificates)
            addCRLs(sdp.crls)
        }.build(bos, true).use { it.write(TestMessage.toByteArray()) }

        verifyEncodedData(bos)

        assertEquals(2, sdp.crls.size)
        assertTrue(sdp.crls.contains(signCrl))
        assertTrue(sdp.crls.contains(origCrl))
    }


    @Test
    fun testSHA256WithRSAOtherCRL() {

        val typedContent = TypedByteArray(TestMessage.toByteArray())
        val certList = listOf(origCert, signCert)
        val crlList = listOf(signCrl, origCrl)

        val certs = CollectionStore(certList)
        val crls = CollectionStore(crlList)


        val infoGen = SignerInfoGenerator(origKP.signingKey, PKCS1SigSpec(Digest.SHA256), certList[0]).apply {
            //withDirectSignature(true)
        }


        val signedData = SignedDataBuilder().apply {
            addCertificates(certs)
            addSignerInfoGenerator(infoGen)
            addCRLs(crls)
        }.build(TypedByteArray(TestMessage.toByteArray()), false)


        checkSigParseable(signedData.encoding)


        val sdp = SignedDataParser(signedData, typedContent.typedStream())
        sdp.signedContent?.drain()


        //
        // compute expected content digest.
        //
        val digest = Digest.SHA256.digestCalculator().apply { stream.use { it.write(typedContent.content) } }.digest()
        verifySignaturesParser(sdp, digest)


        //
        // type using existing signer
        //

        val bos = ByteArrayOutputStream()

        SignedDataStreamBuilder().apply {
            addSigners(sdp.signerInfos)
            addCertificates(sdp.certificates)
            addCRLs(sdp.crls)
        }.build(bos, true).use { it.write(TestMessage.toByteArray()) }

        verifyEncodedData(bos)

        assertEquals(2, sdp.crls.size)
        assertTrue(sdp.crls.contains(signCrl))
        assertTrue(sdp.crls.contains(origCrl))
    }


}
