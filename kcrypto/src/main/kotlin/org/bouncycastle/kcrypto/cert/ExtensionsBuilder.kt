package org.bouncycastle.kcrypto.cert

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.Extensions
import org.bouncycastle.asn1.x509.ExtensionsGenerator
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.kcrypto.PublicKey
import org.bouncycastle.kcrypto.VerificationKey

/**
 * Builder class for X.509 Extensions structures.
 */
class ExtensionsBuilder
{
    private var extGen = ExtensionsGenerator()
    private var extUtils = JcaX509ExtensionUtils()

    /**
     * Add an extension based on the passed in values.
     *
     * @param oid the OID defining the extension type.
     * @param isCritical true if the extension is critical, false otherwise.
     * @param value the ASN.1 structure that forms the extension's value.
     * @return this builder object.
     */
    fun addExtension(extOid: ASN1ObjectIdentifier, isCritical: Boolean, extValue: ASN1Encodable): ExtensionsBuilder {
          extGen.addExtension(extOid, isCritical, extValue)
        return this
    }

    /**
     * Add a SubjectKeyIdentifier based on the passed in public key.
     *
     * @param isCritical true if the extension is critical, false otherwise.
     * @param publicKey the public key the SubjectKeyIdentifier is to be calculated on.
     * @return this builder object.
     */
    fun addSubjectKeyIdentifier(isCritical: Boolean, publicKey: PublicKey): ExtensionsBuilder {
        extGen.addExtension(Extension.subjectKeyIdentifier, isCritical,
                extUtils.createSubjectKeyIdentifier(SubjectPublicKeyInfo.getInstance(publicKey.encoding)))
        return this
    }

    /**
     * Add an AuthorityKeyIdentifier based on the passed X.509 certificate.
     *
     * @param isCritical true if the extension is critical, false otherwise.
     * @param issuerCert the issuer certificate for the certificate this extension is being added to.
     * @return this builder object.
     */
    fun addAuthorityKeyIdentifier(isCritical: Boolean, issuerCert: Certificate): ExtensionsBuilder {
        extGen.addExtension(Extension.authorityKeyIdentifier, isCritical,
                extUtils.createAuthorityKeyIdentifier(issuerCert._cert))
        return this
    }

    /**
     * Add an AuthorityKeyIdentifier based on the passed in verification key.
     *
     * @param isCritical true if the extension is critical, false otherwise.
     * @param publicKey the public key the AuthorityKeyIdentifier is to be calculated on.
     * @return this builder object.
     */
    fun addAuthorityKeyIdentifier(isCritical: Boolean, issuerPublicKey: VerificationKey): ExtensionsBuilder {
        extGen.addExtension(Extension.authorityKeyIdentifier, isCritical,
                extUtils.createAuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(issuerPublicKey.encoding)))
        return this
    }

    fun isEmpty(): Boolean {
        return extGen.isEmpty
    }

    /**
     * Build the final Extensions structure.
     *
     * @return a finalized Extensions structure.
     */
    fun build(): Extensions {
        return extGen.generate()
    }
}
