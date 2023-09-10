package org.bouncycastle.kcrypto.cert.dsl

import org.bouncycastle.asn1.ASN1GeneralizedTime
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.CRLReason
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.Extensions
import org.bouncycastle.kcrypto.cert.*
import org.bouncycastle.kcrypto.dsl.SignatureBlock
import java.math.BigInteger
import java.util.*

fun crl(block: CRLBody.()-> Unit): CRL = CRLBody().apply(block).build()

class CRLBody
{
    var issuer: Certificate? = null
    lateinit var issuerName: X500Name
    var thisUpdate: Date = Date()
    var nextUpdate: Date? = null
    var extensions: Extensions? = null

    private val signature = SignatureBlock()
    private val altSignature = SignatureBlock()
    private val crlEntries = CRLEntryBlock()

    var altSignatureUsed: Boolean = false

    fun build(): CRL
    {
        var crlIssuer = issuer?.subject
        if (crlIssuer != null) {
            issuerName = crlIssuer
        }

        var builder = V2CRLBuilder(issuerName, thisUpdate)

        val next = nextUpdate
        if (next != null) {
            builder.setNextUpdate(next)
        }

        addEntries(builder, crlEntries.entries)

        addExtensions(builder, extensions)

        if (altSignatureUsed) {
            return builder.build(signature.signatureCalculator(), false, altSignature.signatureCalculator())
        }
        return builder.build(signature.signatureCalculator())
    }

    fun signature(block: SignatureBlock.()-> Unit) = signature.apply(block)

    fun altSignature(block: SignatureBlock.()-> Unit) {
        altSignatureUsed = true;
        altSignature.apply(block)
    }

    fun revocation(block: CRLEntryBlock.()-> Unit) = crlEntries.apply(block).addEntry()
}

private fun addEntries(builder: V2CRLBuilder, entries: List<CRLEntryBlock>)
{
    for (e in entries)
    {
        val reason = e.reason
        val exts = e.extensions
        val invalidityDate = e.invalidityDate

        val extBuilder = ExtensionsBuilder()

        if (reason != null) {
            val crlReason = CRLReason.lookup(reason.value)

            extBuilder.addExtension(Extension.reasonCode, false, crlReason)
        }
        if (invalidityDate != null) {
            extBuilder.addExtension(Extension.invalidityDate, false, ASN1GeneralizedTime(invalidityDate))
        }
        if (exts != null) {
            for (oid in exts.oids()) {
                val ext = exts.getExtension(oid as ASN1ObjectIdentifier)
                extBuilder.addExtension(ext.extnId, ext.isCritical, ext.parsedValue)
            }
        }
        if (extBuilder.isEmpty()) {
            builder.addCRLEntry(e.getSerial(), e.revocationDate)
        } else {
            builder.addCRLEntry(e.getSerial(), e.revocationDate, extBuilder.build())
        }
    }
}

private fun addExtensions(builder: V2CRLBuilder, exts: Extensions?)
{
    if (exts != null) {
        for (oid in exts.oids()) {
            builder.addExtension(exts.getExtension(oid as ASN1ObjectIdentifier))
        }
    }
}

infix fun CRL.updateWith(block: CRLUpdateBody.()-> Unit): CRL = CRLUpdateBody().apply(block).build(this)

class CRLUpdateBody
{
    var issuer: Certificate? = null
    lateinit var issuerName: X500Name
    var thisUpdate: Date = Date()
    var nextUpdate: Date? = null
    var extensions: Extensions? = null

    private val signature = SignatureBlock()
    private val altSignature = SignatureBlock()
    private val crlEntries = CRLEntryBlock()

    var altSignatureUsed: Boolean = false

    fun build(crl: CRL): CRL
    {
        var crlIssuer = issuer?.subject
        if (crlIssuer != null) {
            issuerName = crlIssuer
        }

        var builder = V2CRLBuilder(crl)

        val next = nextUpdate
        if (next != null) {
            builder.setNextUpdate(next)
        }

        addEntries(builder, crlEntries.entries)

        addExtensions(builder, extensions)

        if (altSignatureUsed) {
            return builder.build(signature.signatureCalculator(), false, altSignature.signatureCalculator())
        }
        return builder.build(signature.signatureCalculator())
    }

    fun signature(block: SignatureBlock.()-> Unit) = signature.apply(block)

    fun altSignature(block: SignatureBlock.()-> Unit) {
        altSignatureUsed = true;
        altSignature.apply(block)
    }
    
    fun revocation(block: CRLEntryBlock.()-> Unit) = crlEntries.apply(block).addEntry()
}

class CRLEntryBlock {

    val unspecified = RevocationReason.unspecified
    val keyCompromise = RevocationReason.keyCompromise
    val cACompromise = RevocationReason.cACompromise
    val affiliationChanged = RevocationReason.affiliationChanged
    val superseded = RevocationReason.superseded
    val cessationOfOperation = RevocationReason.cessationOfOperation
    val certificateHold = RevocationReason.certificateHold
    // 7 -> unknown
    val removeFromCRL = RevocationReason.removeFromCRL
    val privilegeWithdrawn = RevocationReason.privilegeWithdrawn
    val aACompromise = RevocationReason.aACompromise

    lateinit var userCert: Any
    var revocationDate = Date()
    var reason: RevocationReason?  = null
    var invalidityDate: Date? = null
    var extensions: Extensions? = null

    val entries = ArrayList<CRLEntryBlock>()

    internal fun getSerial(): BigInteger {
        val certDet = userCert

        if (certDet is BigInteger)
        {
            return certDet
        }
        if (certDet is Certificate)
        {
            return certDet.serialNumber
        }
        throw IllegalArgumentException("userCert serial number unknown in CRL entry")
    }

    fun addEntry()
    {
        var e = CRLEntryBlock()

        e.userCert = userCert
        e.revocationDate = revocationDate

        entries.add(e)
    }

    fun entries(): List<CRLEntryBlock> = entries
}
