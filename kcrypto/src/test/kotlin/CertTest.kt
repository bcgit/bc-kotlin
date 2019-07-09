import org.bouncycastle.asn1.ASN1GeneralizedTime
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.kcrypto.Digest
import org.bouncycastle.kcrypto.SigningKeyPair
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
import org.bouncycastle.kcrypto.spec.asymmetric.PKCS1SigSpec
import org.bouncycastle.kcrypto.spec.asymmetric.RSAGenSpec
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.util.*


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

