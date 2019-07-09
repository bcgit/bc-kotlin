package org.bouncycastle.kcrypto.cms

import org.bouncycastle.asn1.cms.AttributeTable
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.cms.CMSAttributeTableGenerator
import org.bouncycastle.kcrypto.Digest
import org.bouncycastle.kcrypto.SignatureCalculator
import org.bouncycastle.kcrypto.SigningKey
import org.bouncycastle.kcrypto.cert.Certificate
import org.bouncycastle.kcrypto.internal.KContentSigner
import org.bouncycastle.kcrypto.internal.KDigestCalculator
import org.bouncycastle.kcrypto.spec.SigAlgSpec
import org.bouncycastle.operator.DigestCalculator
import org.bouncycastle.operator.DigestCalculatorProvider


class SignerInfoGenerator {

    private val associatedCertificate: Certificate
    private val sigCalculator: SignatureCalculator<AlgorithmIdentifier>

    constructor(sigCalculator: SignatureCalculator<AlgorithmIdentifier>, associatedCertificate: Certificate)
    {
        this.associatedCertificate = associatedCertificate
        this.sigCalculator = sigCalculator
    }

    constructor(signingKey: SigningKey, sigAlgSpec: SigAlgSpec, associatedCertificate: Certificate): this(signingKey.signatureCalculator(sigAlgSpec), associatedCertificate)

    private val builder = org.bouncycastle.cms.SignerInfoGeneratorBuilder(KDigestCalculatorProvider())

    fun withDirectSignature(hasNoSignedAttributes: Boolean): SignerInfoGenerator {
        this.builder.setDirectSignature(hasNoSignedAttributes)

        return this
    }

    fun withSignedAttributeGeneration(signedGen: (parameters: Map<String, *>) -> AttributeTable): SignerInfoGenerator {
        this.builder.setSignedAttributeGenerator(TableGen(signedGen))
        return this
    }

    fun withUnsignedAttributeGeneration(unsignedGen: (parameters: Map<String, *>) -> AttributeTable): SignerInfoGenerator {
        this.builder.setUnsignedAttributeGenerator(TableGen(unsignedGen))
        return this
    }

    internal fun generate(): org.bouncycastle.cms.SignerInfoGenerator
    {
        return builder.build(KContentSigner(sigCalculator), associatedCertificate._cert)
    }
}

private class KDigestCalculatorProvider: DigestCalculatorProvider
{
    override fun get(digAlgID: AlgorithmIdentifier?): DigestCalculator {
        return when (digAlgID?.algorithm) {
            NISTObjectIdentifiers.id_sha224 ->  KDigestCalculator(Digest.SHA224.digestCalculator())
            NISTObjectIdentifiers.id_sha256 ->  KDigestCalculator(Digest.SHA256.digestCalculator())
            NISTObjectIdentifiers.id_sha384 ->  KDigestCalculator(Digest.SHA384.digestCalculator())
            NISTObjectIdentifiers.id_sha512 ->  KDigestCalculator(Digest.SHA512.digestCalculator())
            else -> throw IllegalStateException("unknown digest algorithm")
        }
    }
}

private class ImmutableMap<K, V>(private val inner: Map<Any?, Any?>) : Map<K, V> by inner as Map<K, V>

private class TableGen(val signedGen: (parameters: Map<String, *>)-> AttributeTable) : CMSAttributeTableGenerator
{
    override fun getAttributes(p0: MutableMap<Any?, Any?>): AttributeTable {

        return signedGen.invoke(ImmutableMap<String, Any>(p0))
    }
}