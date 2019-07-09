import org.bouncycastle.asn1.cms.CMSAttributes
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator
import org.bouncycastle.kcrypto.Digest
import org.bouncycastle.kcrypto.KeyPair
import org.bouncycastle.kcrypto.KeyType
import org.bouncycastle.kcrypto.SigningKeyPair
import org.bouncycastle.kcrypto.cert.Certificate
import org.bouncycastle.kcrypto.cert.CertificateBuilder
import org.bouncycastle.kcrypto.cms.*
import org.bouncycastle.kcrypto.param.DSADomainParameters
import org.bouncycastle.kcrypto.pkcs.PKCS8EncryptedPrivateKey
import org.bouncycastle.kcrypto.pkcs.PKCS8EncryptedPrivateKeyBuilder
import org.bouncycastle.kcrypto.pkcs.dsl.encryptedPrivateKey
import org.bouncycastle.kcrypto.spec.asymmetric.*
import org.bouncycastle.kcrypto.spec.kdf.ScryptSpec
import org.bouncycastle.kcrypto.spec.symmetric.*
import org.bouncycastle.kutil.ASN1Dump
import org.bouncycastle.kutil.CollectionStore
import org.bouncycastle.kutil.readPEMObject
import org.bouncycastle.kutil.writePEMObject
import org.bouncycastle.util.Strings
import org.bouncycastle.util.encoders.Hex
import java.io.ByteArrayOutputStream
import java.io.File
import java.math.BigInteger
import java.security.SecureRandom
import java.security.spec.RSAKeyGenParameterSpec
import java.util.*

fun main() {

    initProvider()


    var dsaKP = KCryptoServices.signingKeyPair(DSAGenSpec(DSADomainParameters.DEF_2048))

    val dsaSigner = dsaKP.signingKey.signatureCalculator(DSASigSpec(Digest.SHA256))

    dsaSigner.use {
        it.stream.write(ByteArray(30))
    }
    val dsaSig = dsaSigner.signature()

    println(Hex.toHexString(dsaSig))

    var dsaVerifier = dsaKP.verificationKey.signatureVerifier(DSASigSpec(Digest.SHA256))

    dsaVerifier.use {
        it.stream.write(ByteArray(30))
    }
    println("DSA " + dsaVerifier.verifies(dsaSig))

    var kp = KCryptoServices.signingKeyPair(RSAGenSpec(2048))

    val contentSigner = kp.signingKey.signatureCalculator(PSSSigSpec(Digest.SHA256))

    contentSigner.use {
        it.stream.write(ByteArray(30))
    }
    val sig = contentSigner.signature()

    println(Hex.toHexString(sig))

    var contentVerifier = kp.verificationKey.signatureVerifier(PSSSigSpec(Digest.SHA256))

    contentVerifier.stream.write(ByteArray(30))

    contentVerifier.stream.close()

    println("PSS " + contentVerifier.verifies(sig))

    val name = with(X500NameBuilder())
    {
        this.addRDN(BCStyle.C, "AU")
                .addRDN(BCStyle.O, "The Legion of the Bouncy Castle")
                .addRDN(BCStyle.L, "Melbourne")
                .addRDN(BCStyle.CN, "Eric H. Echidna")
                .addRDN(BCStyle.EmailAddress, "feedback-crypto@bouncycastle.org")
                .build()
    }

    var expDate = Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000)
    var cert = with(CertificateBuilder(kp.signingKey, PKCS1SigSpec(Digest.SHA256), name))
    {
        this.setNotBefore(Date())
        this.setNotAfter(expDate)
        this.build(BigInteger.valueOf(7), kp.verificationKey)
    }

    var kp2 = KCryptoServices.signingKeyPair(RSAGenSpec(2048))

    val name2 = with(X500NameBuilder())
    {
        this.addRDN(BCStyle.C, "AU")
                .addRDN(BCStyle.O, "The Legion of the Bouncy Castle")
                .addRDN(BCStyle.L, "Melbourne")
                .addRDN(BCStyle.CN, "Not Eric H. Echidna")
                .addRDN(BCStyle.EmailAddress, "feedback-crypto@bouncycastle.org")
                .build()
    }

    var cert2 = with(CertificateBuilder(kp2.signingKey, PKCS1SigSpec(Digest.SHA256), name2))
    {
        this.setNotBefore(Date())
        this.setNotAfter(expDate)
        this.build(BigInteger.valueOf(7), kp2.verificationKey)
    }

    println(cert.toString() + " " + cert.signatureVerifiedBy(cert));

    File("/tmp/key.pem").writePEMObject(kp.signingKey)

    File("/tmp/cert.pem").writePEMObject(cert)

    var pemKeyPair = File("/tmp/key.pem").readPEMObject<KeyPair?>()

    System.err.println(SigningKeyPair(pemKeyPair as KeyPair))

    var pemCert = File("/tmp/cert.pem").readPEMObject<Certificate?>()

    if (pemCert != null) {
        System.err.println(pemCert.publicKey(KeyType.ENCRYPTION))
        System.err.println(pemCert.signatureVerifiedBy(kp.verificationKey))
    }
    var key = KCryptoServices.symmetricKey(AESGenSpec(256))

    var bOut = ByteArrayOutputStream()
    var aeadEncryptor = key.encryptor(GCMSpec(Hex.decode("000102030405060708090a0b"), 128)).outputEncryptor(bOut)

    aeadEncryptor.use {
        it.aadStream.write(Strings.toByteArray("Hello"))

        it.encStream.write(sig)
    }

    println(Hex.toHexString(bOut.toByteArray()))

    var b2Out = ByteArrayOutputStream()
    var dOut = key.decryptor(GCMSpec(aeadEncryptor.algorithmIdentifier)).outputDecryptor(b2Out)

    dOut.aadStream.write(Strings.toByteArray("Hello"))

    dOut.decStream.write(bOut.toByteArray())

    dOut.decStream.close()

    println(Hex.toHexString(b2Out.toByteArray()))
    println(Hex.toHexString(sig))

    b2Out = ByteArrayOutputStream()
    dOut = key.decryptor(GCMSpec(aeadEncryptor.algorithmIdentifier)).outputDecryptor(b2Out)

    dOut.aadStream.write(Strings.toByteArray("Hello"))

    dOut.decStream.write(bOut.toByteArray())

    dOut.decStream.close()

    println(Hex.toHexString(b2Out.toByteArray()))
    println(Hex.toHexString(sig))

    var ekp = KCryptoServices.encryptingKeyPair(RSAGenSpec(2048))

    var encryptor = ekp.singleBlockEncryptor(OAEPSpec(Digest.SHA1))

    var enc = encryptor.encrypt(Strings.toByteArray("Hello"))

    println(Hex.toHexString(enc))

    var decryptor = ekp.singleBlockDecryptor(OAEPSpec(Digest.SHA1))

    println(Strings.fromByteArray(decryptor.decrypt(enc)))

    var wrap = ekp.keyWrapper(OAEPSpec(Digest.SHA1)).wrap(key)

    println(Hex.toHexString(wrap))

    var symUnwrap = ekp.keyUnwrapper(OAEPSpec(Digest.SHA1)).unwrap(wrap, AESGenSpec.symType)

    var smallKp = KCryptoServices.signingKeyPair(RSAGenSpec(256, RSAKeyGenParameterSpec.F0, SecureRandom()))

    ekp = KCryptoServices.encryptingKeyPair(RSAGenSpec(8192))

    var asymWrap = ekp.keyWrapper(OAEPSpec(Digest.SHA1)).wrap(smallKp.signingKey)

    var asymUnwrap = ekp.keyUnwrapper(OAEPSpec(Digest.SHA1)).unwrap(asymWrap, KeyType.DECRYPTION)

    println(Hex.toHexString(smallKp.signingKey.encoding))

    val keyWrapper = key.keyWrapper(KWPSpec())

    var kwp = keyWrapper.wrap(smallKp.signingKey)

    var kwpUnwrap = key.keyUnwrapper(KWPSpec(keyWrapper.algorithmIdentifier)).unwrap(kwp, KeyType.DECRYPTION)

    println(Hex.toHexString(kwpUnwrap.encoding))

    var dc = Digest.SHA256.digestCalculator()

    dc.stream.write(Strings.toByteArray("Hello, World!"))

    dc.stream.close()

    var dig = dc.digest()

    println(Hex.toHexString(dig))

    var dv = Digest.SHA256.digestVerifier()

    dv.stream.write(Strings.toByteArray("Hello, World!"))

    dv.stream.close()

    println(dv.verify(dig))

    var wrapCipher = key.encryptor(GCMSpec(aeadEncryptor.algorithmIdentifier))

    var bldr = PKCS8EncryptedPrivateKeyBuilder(smallKp.signingKey)

    var encInfo = bldr.build(wrapCipher)

    var sKey = encInfo.privateKey(key, KeyType.DECRYPTION)

    File("/tmp/priv.pem").writePEMObject(encInfo)

    var pemPriv = File("/tmp/priv.pem").readPEMObject<PKCS8EncryptedPrivateKey>() as PKCS8EncryptedPrivateKey

    sKey = pemPriv.privateKey(key, KeyType.DECRYPTION)

    System.err.println("@@ " + Hex.toHexString(sKey.encoding))

    val scrypt = ScryptSpec(20, 1048576, 8, 1)
 
    var keyq = KCryptoServices.pbkdf(scrypt, AESGenSpec(256)).symmetricKey("Hello, world!".toCharArray())

    System.err.println(Hex.toHexString(keyq.encoding))
    var kwpCipher = keyq.encryptor(KWPSpec())

    bldr = PKCS8EncryptedPrivateKeyBuilder(smallKp.signingKey)

    encInfo = bldr.build(kwpCipher)

    if (encInfo.isPBEBased) {

        var k = encInfo.pbkdf?.symmetricKey("Hello, world!".toCharArray())
        if (k != null) {
            sKey = encInfo.privateKey(k, KeyType.DECRYPTION)
            System.err.println("%% " + Hex.toHexString(sKey.encoding))
        }
    }

    var encKey = encryptedPrivateKey {
        privateKey = smallKp.signingKey
        encryption {
            AESGCM tagSize 128 using PBKDF2 {
                saltLength = 20
                iterationCount = 4096
                prf = sha256
            } with "Test".toCharArray()
        }
    }

    if (encKey.isPBEBased) {

        var k = encKey.pbkdf?.symmetricKey("Test".toCharArray())

        if (k != null) {
            sKey = encKey.privateKey(k, KeyType.DECRYPTION)
            System.err.println("%% " + Hex.toHexString(sKey.encoding))
        }
    }

    var hmacK = KCryptoServices.macKey(HMacSHA256GenSpec(256))

    bOut = ByteArrayOutputStream()

    var certs = CollectionStore(cert, cert2)

    var gen = SignedDataStreamBuilder()

    gen.addSignerInfoGenerator(SignerInfoGenerator(kp.signingKey, PKCS1SigSpec(Digest.SHA256), cert))

    gen.addCertificates(certs)

    var sigOut = gen.build(bOut, true)

    sigOut.write("Hello, world!".toByteArray())

    sigOut.close()

    val sp = SignedDataParser(bOut.toByteArray())

    sp.signedContent?.drain()

    var st = sp.signerInfos

    var signer = st.first()

    println(signer.signatureVerifiedBy(kp.verificationKey))

    var cb = CertificateManagementMessageBuilder()

    cb.addCertificate(cert)

    var cm = cb.build()

    for (cert in cm.certificates) {
        println(cert.toString())
    }

    var sd = SignedData(bOut.toByteArray())

    println(sd.isCertificateManagementMessage)
    println(sd.signedContent?.content)

    println(sd.signerInfos.first().certificateID.matches(cert))
    println(sd.signerInfos.first().signerID.matches(sd.signerInfos.first()))

    var signerInfo = sd.signerInfos.first()

    println(sd.signerInfos.match(signerInfo.signerID))
    println(sd.certificates.match(signerInfo.certificateID))

    var gen2 = SignedDataBuilder()

    val infoGenerator = SignerInfoGenerator(kp.signingKey, PKCS1SigSpec(Digest.SHA256), cert)

    infoGenerator.withSignedAttributeGeneration {
        val table = DefaultSignedAttributeTableGenerator().getAttributes(it)

        table.remove(CMSAttributes.cmsAlgorithmProtect)
    }


    gen2.addSignerInfoGenerator(infoGenerator)

    gen2.addCertificates(certs)

    var sd2 = gen2.build(TypedByteArray("Hello, world!".toByteArray()), true)

    signer = sd2.signerInfos.first()

    println("&&& " + signer.signedAttributes.get(CMSAttributes.cmsAlgorithmProtect))

    val cert3 = sd2.certificates.match(signer.certificateID)
    if (cert3 != null) {
        println(sd2.signerInfos.first().signatureVerifiedBy(cert3))
    }

    println("## " + sd2.allSignaturesVerify(certs))

    val macKey = KCryptoServices.macKey(HMacSHA256GenSpec(256))
    var macCalc = macKey.macCalculator(HMacSpec())

    macCalc.use {
        it.stream.write(ByteArray(30))
    }
    val mac = macCalc.mac()

    var macVer = macKey.macVerifier(HMacSpec())

    macVer.use {
        it.stream.write(ByteArray(30))
    }
    println(macVer.verifies(mac))
    println(ASN1Dump.dumpAsString(macVer.algorithmIdentifier))

    val cmacKey = KCryptoServices.macKey(AESGenSpec(256))
    var cmacCalc = cmacKey.macCalculator(CCMSpec())

    cmacCalc.use {
        it.stream.write(ByteArray(30))
    }
    val cmac = cmacCalc.mac()

    var cmacVer = cmacKey.macVerifier(CCMSpec(cmacCalc.algorithmIdentifier))

    cmacVer.use {
        it.stream.write(ByteArray(30))
    }
    println(cmacVer.verifies(cmac))
    println(ASN1Dump.dumpAsString(cmacVer.algorithmIdentifier))
}
