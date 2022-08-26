import org.bouncycastle.asn1.ASN1GeneralizedTime
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DERPrintableString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.util.ASN1Dump
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.kcrypto.Digest
import org.bouncycastle.kcrypto.SigningKeyPair
import org.bouncycastle.kcrypto.cert.CRL
import org.bouncycastle.kcrypto.cert.Certificate
import org.bouncycastle.kcrypto.cert.CertificateBuilder
import org.bouncycastle.kcrypto.cert.dsl.*
import org.bouncycastle.kcrypto.dsl.rsa
import org.bouncycastle.kcrypto.dsl.signingKeyPair
import org.bouncycastle.kcrypto.pkcs.PKCS10Request
import org.bouncycastle.kcrypto.pkcs.dsl.attribute
import org.bouncycastle.kcrypto.pkcs.dsl.attributes
import org.bouncycastle.kcrypto.pkcs.dsl.pkcs10Request
import org.bouncycastle.kcrypto.spec.asymmetric.ECDSASigSpec
import org.bouncycastle.kcrypto.spec.asymmetric.ECGenSpec
import org.bouncycastle.kcrypto.spec.asymmetric.RSAGenSpec
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.io.FileOutputStream
import java.math.BigInteger
import java.util.*
import kotlin.experimental.xor


@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CertTest {

    val taKP: SigningKeyPair
    val taDN: X500Name


    val caKP: SigningKeyPair

    val endKp: SigningKeyPair

    val endDN: X500Name
    val caDN: X500Name

    init {

        initProvider()

        taKP = KCryptoServices.signingKeyPair(ECGenSpec("P-256"))

        caKP = KCryptoServices.signingKeyPair(ECGenSpec("P-256"))

        // Just for testing use bigger size in any real world application!
        endKp = KCryptoServices.signingKeyPair(RSAGenSpec(1024))


        taDN = x500Name {
            rdn(BCStyle.C, "AU")
            rdn(BCStyle.O, "The Legion of the Bouncy Castle")
            rdn(BCStyle.L, "Melbourne")
            rdn(BCStyle.CN, "Trust Anchor")
            rdn(BCStyle.EmailAddress, "feedback-crypto@bouncycastle.org")
        }

        endDN = x500Name {
            rdn(BCStyle.C, "AU")
            rdn(BCStyle.O, "The Legion of the Bouncy Castle")
            rdn(BCStyle.L, "Melbourne")
            rdn(BCStyle.CN, "Eric H. Echidna")
            rdn(BCStyle.EmailAddress, "feedback-crypto@bouncycastle.org")
        }

        caDN = x500Name {
            rdn(BCStyle.C, "AU")
            rdn(BCStyle.O, "The Legion of the Bouncy Castle")
            rdn(BCStyle.L, "Melbourne")
            rdn(BCStyle.CN, "Sir Robert Peel")
            rdn(BCStyle.EmailAddress, "bobbies@bouncycastle.org")
        }
    }

    @Test
    fun `create crl`() {

        var expDate = Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000)

        var name = x500Name {
            rdn(BCStyle.C, "AU")
            rdn(BCStyle.O, "The Legion of the Bouncy Castle")
            rdn(BCStyle.L, "Melbourne")
            rdn(BCStyle.CN, "Eric H. Echidna")
            rdn(BCStyle.EmailAddress, "feedback-crypto@bouncycastle.org")
        }


        val cert = certificate {
            serialNumber = BigInteger.valueOf(1)
            issuer = name
            notAfter = expDate
            subject = name
            subjectPublicKey = caKP.verificationKey

            signature {
                ECDSA with sha256 using caKP.signingKey
            }
        }


        val exts = extensions {
            authorityKeyIdentifierExtension {
                authorityKey = cert
            }
        }


        val crl = crl {
            issuer = cert

            revocation {
                userCert = BigInteger.ONE
                reason = certificateHold
            }
            revocation {
                userCert = cert
                reason = keyCompromise
            }

            extensions = exts

            signature {
                ECDSA with sha256 using caKP.signingKey
            }
        }

        //
        // Basic verification test.
        //
        assertTrue(crl.signatureVerifiedBy(cert))

        // Vandalise CRL.
        val enc = crl.encoding

        // We need a location that corrupts data rather than ASN1 Structure.
        enc[10] = enc[10] xor 1
        assertFalse(CRL(enc).signatureVerifiedBy(cert))

        val resCRL = CRL(crl.encoding)
        assertArrayEquals(crl.extensions.encoded, resCRL.extensions.encoded)
        assertArrayEquals(crl.issuer.encoded, resCRL.issuer.encoded)
        assertTrue(crl.signatureVerifiedBy(caKP.verificationKey))


        var left = crl.findEntryForRevokedCertificate(BigInteger.ONE)!!
        var right = resCRL.findEntryForRevokedCertificate(BigInteger.ONE)!!
        assertEquals(left.serialNumber, right.serialNumber)
        assertEquals(left.revocationDate, right.revocationDate)
        assertEquals(left.hasExtensions, right.hasExtensions)
        assertArrayEquals(left.extensions.encoded, right.extensions.encoded)



        left = crl.findEntryForRevokedCertificate(cert.serialNumber)!!
        right = resCRL.findEntryForRevokedCertificate(cert.serialNumber)!!
        assertEquals(left.serialNumber, right.serialNumber)
        assertEquals(left.revocationDate, right.revocationDate)
        assertEquals(left.hasExtensions, right.hasExtensions)
        assertArrayEquals(left.extensions.encoded, right.extensions.encoded)


    }


    @Test
    fun `pkcs10 request`() {


        val kp = signingKeyPair {
            rsa {
                keySize = 2048
            }
        }


        val pkcs10Req = pkcs10Request {
            subject = x500Name {
                rdn(BCStyle.C, "AU")
                rdn(BCStyle.O, "The Legion of the Bouncy Castle")
                rdn(BCStyle.L, "Melbourne")
                rdn(BCStyle.CN, "Eric H. Echidna")
                rdn(BCStyle.EmailAddress, "feedback-crypto@bouncycastle.org")
            }
            subjectKey = kp.verificationKey
            attributes = attributes {
                attribute {
                    attrType = PKCSObjectIdentifiers.pkcs_9_at_extensionRequest
                    attrValue = extensions {
                        critical(extension {
                            extOid = Extension.basicConstraints
                            extValue = BasicConstraints(true)
                        })
                        critical(extension {
                            extOid = Extension.keyUsage
                            extValue = KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign)
                        })
                        subjectKeyIdentifierExtension {
                            subjectKey = kp.verificationKey
                        }
                    }
                }
            }

            signature {
                PKCS1v1dot5 with sha256 using kp.signingKey
            }
        }


        //
        // Create from encoded version
        //
        val rcvReq = PKCS10Request(pkcs10Req.encoding)


        //
        // Verifies with public key.
        //
        assertTrue(rcvReq.signatureVerifiedBy(kp.verificationKey))


        // Subject
        assertArrayEquals(pkcs10Req._request.subject.encoded, rcvReq._request.subject.encoded)


        //
        // Check off the name.
        //
        val attr = rcvReq._request.attributes.asList()
        val originalAttr = pkcs10Req._request.attributes

        assertEquals(originalAttr.size, attr.size)

        originalAttr.withIndex().forEach {
            assertArrayEquals(it.value.encoded, attr[it.index].encoded)
        }


    }

    @Test
    fun `test x500Name`() {

        val fields = listOf<ASN1ObjectIdentifier>(
                BCStyle.C,
                BCStyle.O,
                BCStyle.OU,
                BCStyle.T,
                BCStyle.CN,
                BCStyle.SN,
                BCStyle.STREET,
                BCStyle.SERIALNUMBER,
                BCStyle.L,
                BCStyle.ST,
                BCStyle.SURNAME,
                BCStyle.GIVENNAME,
                BCStyle.INITIALS,
                BCStyle.GENERATION,
                BCStyle.UNIQUE_IDENTIFIER,
                BCStyle.BUSINESS_CATEGORY,
                BCStyle.POSTAL_CODE,
                BCStyle.DN_QUALIFIER,
                BCStyle.PSEUDONYM,
                BCStyle.PLACE_OF_BIRTH,
                BCStyle.GENDER,
                BCStyle.COUNTRY_OF_CITIZENSHIP,
                BCStyle.COUNTRY_OF_RESIDENCE,
                BCStyle.POSTAL_ADDRESS,
                BCStyle.DMD_NAME,
                BCStyle.TELEPHONE_NUMBER,
                BCStyle.NAME,
                BCStyle.EmailAddress,
                BCStyle.UnstructuredName,
                BCStyle.UnstructuredAddress,
                BCStyle.E,
                BCStyle.DC,
                BCStyle.UID
        )


        var ctr = 0
        val valueSet = fields.map {
            val left = it
            val right = if (BCStyle.DATE_OF_BIRTH.equals(left)) {
                ASN1GeneralizedTime(Date()).time
            } else {
                "" + ctr++
            }
            Pair(left, right)
        }


        val tstName = x500Name {
            valueSet.forEach { field ->
                rdn(field.first, field.second)
            }
        }


        val rstName = x500Name(tstName.encoded)


        assertTrue(rstName.equals(tstName))

        val str = rstName.toString();

        assertTrue(tstName.equals(x500Name(str)))

    }


    @Test
    fun `selfsigned cert has correct DNs`() {

        val expDate = Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000)


        val ext = extensions {
            critical(extension {
                extOid = Extension.basicConstraints
                extValue = BasicConstraints(true)
            })
            critical(extension {
                extOid = Extension.keyUsage
                extValue = KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign)
            })
            subjectKeyIdentifierExtension {
                subjectKey = caKP.verificationKey
            }
        }

        val selfSigned = with(CertificateBuilder(caKP.signingKey, ECDSASigSpec(Digest.SHA256), caDN))
        {
            this.setNotBefore(java.util.Date())
                    .setNotAfter(expDate)
                    .setExtensions(ext)
                    .build(java.math.BigInteger.valueOf(7), caKP.verificationKey)
        }


        val certRes = Certificate(selfSigned.encoding)

        assertArrayEquals(ext.encoded, certRes._cert.extensions.encoded)

    }

    @Test
    fun `selfsigned cert with extensions`() {

        val expDate = Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000)

        val selfSigned = with(CertificateBuilder(caKP.signingKey, ECDSASigSpec(Digest.SHA256), caDN))
        {
            this.setNotBefore(java.util.Date())
                    .setNotAfter(expDate)


                    .build(java.math.BigInteger.valueOf(7), caKP.verificationKey)


        }


        val certRes = Certificate(selfSigned.encoding)
        assertTrue(caDN.equals(certRes.issuer))
        assertTrue(caDN.equals(certRes.subject))

    }

    @Test
    fun `selfsigned cert with SubjectPublicKeyInfo only authKeyId`() {

        val expDate = Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000)

        var name = x500Name {
            rdn(BCStyle.C, "AU")
            rdn(BCStyle.O, "The Legion of the Bouncy Castle")
            rdn(BCStyle.L, "Melbourne")
            rdn(BCStyle.CN, "Eric H. Echidna")
            rdn(BCStyle.EmailAddress, "feedback-crypto@bouncycastle.org")
        }

        var exts = extensions {
            extension {
                extOid = Extension.basicConstraints
                extValue = BasicConstraints(false)
            }
            subjectKeyIdentifierExtension {
                subjectKey = caKP.verificationKey
            }
            authorityKeyIdentifierExtension {
                authorityKey = SubjectPublicKeyInfo.getInstance(caKP.verificationKey.encoding)
            }
        }

        var selfSigned = certificate {
            serialNumber = BigInteger.valueOf(1)
            issuer = name
            notAfter = expDate
            subject = name
            subjectPublicKey = caKP.verificationKey
            extensions = exts
            
            signature {
                ECDSA with sha256 using caKP.signingKey
            }
        }

        val certRes = Certificate(selfSigned.encoding)
        assertTrue(name.equals(certRes.issuer))
        assertTrue(name.equals(certRes.subject))
    }

    @Test
    fun `selfsigned cert with SubjectAlt and IssuerAlt`() {

        val expDate = Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000)

        var name = x500Name {
            rdn(BCStyle.C, "AU")
            rdn(BCStyle.O, "The Legion of the Bouncy Castle")
            rdn(BCStyle.L, "Melbourne")
            rdn(BCStyle.CN, "Eric H. Echidna")
            rdn(BCStyle.EmailAddress, "feedback-crypto@bouncycastle.org")
        }

        var exts = extensions {
            extension {
                extOid = Extension.basicConstraints
                extValue = BasicConstraints(false)
            }
            subjectAltNameExtension {
                rfc822Name("test1@test")
                email("test1@test")
                dNSName("bouncycastle.org")
                iPAddress("10.9.7.6")
                registeredID("1.2.3") // OID
                directoryName("CN=Test")
            }
            issuerAltNameExtension {
                rfc822Name("test1@test")
                email("test1@test")
                uniformResourceIdentifier("https://www.bouncycastle.org/1")
                uri("https://www.bouncycastle.org/2")
                url("https://www.bouncycastle.org/3")
                directoryName(name)
                generalName(GeneralName.otherName, DERSequence(DERPrintableString("Other")))
            }
        }

        var selfSigned = certificate {
            serialNumber = BigInteger.valueOf(1)
            issuer = name
            notAfter = expDate
            subject = name
            subjectPublicKey = caKP.verificationKey
            extensions = exts

            signature {
                ECDSA with sha256 using caKP.signingKey
            }
        }

        val certRes = Certificate(selfSigned.encoding)
        assertTrue(name.equals(certRes.issuer))
        assertTrue(name.equals(certRes.subject))
        FileOutputStream("/tmp/fred.crt").write(selfSigned._cert.encoded)
    }

    @Test
    @Disabled("needs kotlin certpath api")
    fun `cert has correct subject and issuer`() {

        val expDate = Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000)

        val ta = with(CertificateBuilder(taKP.signingKey, ECDSASigSpec(Digest.SHA256), taDN))
        {
            this.setNotBefore(java.util.Date())
                    .setNotAfter(expDate)
                    .setExtensions(extensions {
                        basicConstraintsExtension { BasicConstraints(true) }
                        subjectKeyIdentifierExtension {
                            subjectKey = taKP.verificationKey
                        }
                        authorityKeyIdentifierExtension {
                            authorityKey = taKP.verificationKey
                        }
                    })
                    .build(java.math.BigInteger.valueOf(7), taDN, taKP.verificationKey)
        }


        val ca = with(CertificateBuilder(taKP.signingKey, ECDSASigSpec(Digest.SHA256), taDN))
        {

            setNotBefore(java.util.Date())
            setNotAfter(expDate)
            setExtensions(extensions {
                basicConstraintsExtension { BasicConstraints(true) }
                subjectKeyIdentifierExtension {
                    subjectKey = caKP.verificationKey
                }
                authorityKeyIdentifierExtension {
                    authorityKey = ta
                }
            })
                    .build(java.math.BigInteger.valueOf(7), caDN, caKP.verificationKey)
        }


        val ee = with(CertificateBuilder(caKP.signingKey, ECDSASigSpec(Digest.SHA256), caDN)) {
            setNotBefore(java.util.Date())
            setNotAfter(expDate)

            setExtensions(extensions {
                basicConstraintsExtension { BasicConstraints(false) }
                subjectKeyIdentifierExtension {
                    subjectKey = endKp.verificationKey
                }
                authorityKeyIdentifierExtension {
                    authorityKey = ca
                }
            })
                    .build(java.math.BigInteger.valueOf(7), endDN, endKp.verificationKey)
        }


    }


}

