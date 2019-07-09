package org.bouncycastle.kcrypto.cert.dsl

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.Extensions
import org.bouncycastle.kcrypto.VerificationKey
import org.bouncycastle.kcrypto.cert.Certificate
import org.bouncycastle.kcrypto.cert.CertificateBuilder
import org.bouncycastle.kcrypto.dsl.SignatureBlock
import java.math.BigInteger
import java.util.*

fun certificate(block: CertBody.()-> Unit): Certificate = CertBody().apply(block).build()

class CertBody
{
    lateinit var issuer: Any
    lateinit var subject: X500Name
    lateinit var serialNumber: BigInteger
    var notAfter: Date = Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000) // one year
    var notBefore: Date = Date(System.currentTimeMillis() - 1000)
    var extensions: Extensions? = null
    lateinit var subjectPublicKey: VerificationKey

    private val signature = SignatureBlock()

    fun build(): Certificate
    {
        var issuerName: X500Name
        var certIssuer = issuer
        if (certIssuer is Certificate) {
            issuerName = certIssuer.subject
        } else if (certIssuer is X500Name) {
            issuerName = certIssuer
        } else {
            throw IllegalArgumentException("unknown issuer type")
        }

        var builder = CertificateBuilder(signature.signatureCalculator(), issuerName)

        builder.setNotAfter(notAfter)
        builder.setNotBefore(notBefore)

        if (extensions != null) {
            builder.setExtensions(extensions)
        }

        return builder.build(serialNumber, subject, subjectPublicKey)
    }

    fun signature(block: SignatureBlock.()-> Unit) = signature.apply(block)
}


