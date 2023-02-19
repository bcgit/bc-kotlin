package org.bouncycastle.kcrypto.cert.dsl

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.kcrypto.PublicKey
import org.bouncycastle.kcrypto.VerificationKey
import org.bouncycastle.kcrypto.cert.Certificate
import org.bouncycastle.kcrypto.cert.ExtensionsBuilder

class ExtensionsBody
{
    internal val extensions: MutableList<Ext> = ArrayList<Ext>()
    internal val extUtils = JcaX509ExtensionUtils()

    fun addExtension(e: Ext)
    {
        extensions.add(e)
    }

    fun markLastCritical(ve: Ext): Ext
    {
        var e: Ext = extensions.last()

        extensions.removeAt(extensions.size - 1)

        if (e != ve) {
            throw IllegalStateException("extension confusion!")
        }
        
        var ce = Ext(true);
        ce.extOid = e.extOid
        ce.extValue = e.extValue;

        extensions.add(ce)

        return ce
    }

    fun build(): Extensions
    {
        var bldr = ExtensionsBuilder()

        for (e in extensions)
        {
            bldr.addExtension(e.extOid, e.isCritical, e.extValue)
        }

        return bldr.build()
    }
}

fun extensions(block: ExtensionsBody.() -> Unit): Extensions = ExtensionsBody().apply(block).build()

fun ExtensionsBody.extension(block: Ext.() -> Unit): Ext
{
    var e = Ext(false).apply(block)
    addExtension(e)
    return e
}

infix fun ExtensionsBody.critical(e: Ext): Ext {
    return markLastCritical(e)
}

fun ExtensionsBody.subjectKeyIdentifierExtension(block: ExtSubjectKeyId.() -> Unit): Ext
{
    var es = ExtSubjectKeyId().apply(block)

    var e = Ext(false)
    e.extOid = Extension.subjectKeyIdentifier
    e.extValue = extUtils.createSubjectKeyIdentifier(SubjectPublicKeyInfo.getInstance(es.subjectKey.encoding))

    addExtension(e)

    return e
}

fun ExtensionsBody.basicConstraintsExtension(block: ExtBasicConstraints.() -> Unit): Ext
{
    var es = ExtBasicConstraints().apply(block)

    var e = Ext(false)
    e.extOid = Extension.basicConstraints
    if (es.pathLen >= 0) {
        e.extValue = BasicConstraints(es.pathLen)
    } else {
        e.extValue = BasicConstraints(es.isCA)
    }
    addExtension(e)

    return e
}

fun ExtensionsBody.authorityKeyIdentifierExtension(block: ExtAuthorityKeyId.() -> Unit): Ext
{
    var ea = ExtAuthorityKeyId().apply(block)

    var e = Ext(false)
    e.extOid = Extension.authorityKeyIdentifier

    if (ea.authorityKey is Certificate) {
        e.extValue = extUtils.createAuthorityKeyIdentifier((ea.authorityKey as Certificate)._cert)
    }
    else if (ea.authorityKey is VerificationKey)
    {
        e.extValue = extUtils.createAuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance((ea.authorityKey as VerificationKey).encoding))
    }
    else if (ea.authorityKey is SubjectPublicKeyInfo)
    {
        e.extValue = extUtils.createAuthorityKeyIdentifier(ea.authorityKey as SubjectPublicKeyInfo)
    }
    else
    {
        throw IllegalArgumentException("unknown authorityKey type")
    }

    addExtension(e)

    return e
}

fun ExtensionsBody.subjectAltNameExtension(block: GeneralNamesBuilder.() -> Unit): Ext
{
    var e = Ext(false)
    e.extOid = Extension.subjectAlternativeName
    e.extValue = GeneralNamesBuilder().apply(block).build()
    addExtension(e)

    return e
}

fun ExtensionsBody.subjectAltPublicKeyInfoExtension(block: ExtSubjectAltPublicKeyInfo.() -> Unit): Ext
{
    var ea = ExtSubjectAltPublicKeyInfo().apply(block)
    var e = Ext(ea.isCritical)

    e.extOid = Extension.subjectAltPublicKeyInfo
    e.extValue = SubjectAltPublicKeyInfo(SubjectPublicKeyInfo.getInstance(ea.publicKey.encoding))

    addExtension(e)

    return e
}

fun ExtensionsBody.issuerAltNameExtension(block: GeneralNamesBuilder.() -> Unit): Ext
{
    var e = Ext(false)
    e.extOid = Extension.issuerAlternativeName
    e.extValue = GeneralNamesBuilder().apply(block).build()
    addExtension(e)

    return e
}

data class Ext(internal val isCritical: Boolean = false)
{
    lateinit var extOid: ASN1ObjectIdentifier
    lateinit var extValue: ASN1Encodable
}

data class ExtSubjectKeyId(var isCritical: Boolean = false)
{
    lateinit var subjectKey: PublicKey
}

data class ExtBasicConstraints(var isCritical: Boolean = false)
{
    var pathLen: Int = -1
    var isCA: Boolean = false
}

data class ExtAuthorityKeyId(var isCritical: Boolean = false)
{
    lateinit var authorityKey: Any
}

data class ExtSubjectAltPublicKeyInfo(var isCritical: Boolean = false)
{
    lateinit var publicKey: PublicKey
}

fun GeneralNamesBuilder.email(value: String) {
    addName(GeneralName(GeneralName.rfc822Name, value))
}

fun GeneralNamesBuilder.rfc822Name(value: String) {
    addName(GeneralName(GeneralName.rfc822Name, value))
}

fun GeneralNamesBuilder.iPAddress(value: String) {
    addName(GeneralName(GeneralName.iPAddress, value))
}

fun GeneralNamesBuilder.directoryName(value: String) {
    addName(GeneralName(GeneralName.directoryName, value))
}

fun GeneralNamesBuilder.directoryName(value: X500Name) {
    addName(GeneralName(value))
}

fun GeneralNamesBuilder.dNSName(value: String) {
    addName(GeneralName(GeneralName.dNSName, value))
}

fun GeneralNamesBuilder.uniformResourceIdentifier(value: String) {
    addName(GeneralName(GeneralName.uniformResourceIdentifier, value))
}

fun GeneralNamesBuilder.uri(value: String) {
    addName(GeneralName(GeneralName.uniformResourceIdentifier, value))
}

fun GeneralNamesBuilder.url(value: String) {
    addName(GeneralName(GeneralName.uniformResourceIdentifier, value))
}

fun GeneralNamesBuilder.registeredID(value: String) {
    addName(GeneralName(GeneralName.registeredID, value))
}

fun GeneralNamesBuilder.generalName(id: Int, value: ASN1Encodable) {
    addName(GeneralName(id, value))
}

