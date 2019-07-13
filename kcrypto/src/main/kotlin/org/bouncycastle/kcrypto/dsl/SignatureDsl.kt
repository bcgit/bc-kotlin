package org.bouncycastle.kcrypto.dsl

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.Digest
import org.bouncycastle.kcrypto.SignatureCalculator
import org.bouncycastle.kcrypto.SigningKey
import org.bouncycastle.kcrypto.VerificationKey
import org.bouncycastle.kcrypto.pkcs.PKCS10RequestBuilder
import org.bouncycastle.kcrypto.spec.SigAlgSpec
import org.bouncycastle.kcrypto.spec.asymmetric.DSASigSpec
import org.bouncycastle.kcrypto.spec.asymmetric.ECDSASigSpec
import org.bouncycastle.kcrypto.spec.asymmetric.EdDSASigSpec
import org.bouncycastle.kcrypto.spec.asymmetric.PKCS1SigSpec


interface SigType
{
}

interface DigSigType: SigType
{
    fun getSigAlgSpec(digest: Digest): SigAlgSpec
}

interface NoDigSigType: SigType
{
    fun getSigAlgSpec(): SigAlgSpec
}

/**
 * DSL for PKCS1 Signature type.
 */
class PKCS1SigType: DigSigType
{
    override fun getSigAlgSpec(digest: Digest): SigAlgSpec {
        return PKCS1SigSpec(digest)
    }
}

/**
 * DSL for ECDSA signature type.
 */
class ECDSASigType: DigSigType
{
    override fun getSigAlgSpec(digest: Digest): SigAlgSpec {
        return ECDSASigSpec(digest)
    }
}

/**
 * DSL for DSA signature type.
 */
class DSASigType: DigSigType
{
    override fun getSigAlgSpec(digest: Digest): SigAlgSpec {
        return DSASigSpec(digest)
    }
}

/**
 * DSL for EdDSA signature type.
 */
class EdDSASigType: NoDigSigType
{
    override fun getSigAlgSpec(): SigAlgSpec {
        return EdDSASigSpec()
    }
}

/**
 * DSL for block whose methods will return a calculator or a pkcs10RequestBuilder
 */
class SignatureBlock
{
    fun signatureCalculator(): SignatureCalculator<AlgorithmIdentifier> {
        return signature.signingKey.signatureCalculator(signature.getSigAlgSpec())
    }

    fun pkcs10RequestBuilder(subject: X500Name, verificationKey: VerificationKey): PKCS10RequestBuilder {
        return PKCS10RequestBuilder(signature.signingKey, signature.getSigAlgSpec(), subject, verificationKey)
    }

    lateinit var signature: SignatureDetails

    val PKCS1v1dot5 = SignatureDetails(this, PKCS1SigType())
    val ECDSA = SignatureDetails(this, ECDSASigType())
    val DSA = SignatureDetails(this, DSASigType())
    val EdDSA = SignatureDetails(this, EdDSASigType())

    val sha224 = Digest.SHA224
    val sha256 = Digest.SHA256
    val sha384 = Digest.SHA384
    val sha512 = Digest.SHA512
}

/**
 * DSL for specifying the details of the Signature.
 */
class SignatureDetails(val parent: SignatureBlock, val sigType: SigType)
{

    lateinit var signingKey: SigningKey

    var digest: Digest? = null

    infix fun with(digest: Digest): SignatureDetails {

        parent.signature = this;
        this.digest = digest

        return this
    }

    infix fun using(signingKey: SigningKey): SignatureDetails {
        parent.signature = this;
        this.signingKey = signingKey

        return this
    }

    fun getSigAlgSpec(): SigAlgSpec {
        val dig = digest;
        if (dig != null) {
            return (sigType as DigSigType).getSigAlgSpec(dig)
        } else {
            return (sigType as NoDigSigType).getSigAlgSpec()
        }
    }
}