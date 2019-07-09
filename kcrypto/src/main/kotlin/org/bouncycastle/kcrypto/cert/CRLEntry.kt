package org.bouncycastle.kcrypto.cert

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.cert.X509CRLEntryHolder
import java.math.BigInteger

class CRLEntry {
    private val _entry: X509CRLEntryHolder

    internal constructor(entry: X509CRLEntryHolder) {
        _entry = entry
    }

    val serialNumber: BigInteger get() = _entry.serialNumber
    val revocationDate get() = _entry.revocationDate
    val hasExtensions get() = _entry.hasExtensions()
    val certificateIssuer get() = _entry.certificateIssuer
    fun extension(oid: ASN1ObjectIdentifier) = _entry.getExtension(oid)
    val extensions get() = _entry.extensions
    val extensionOIDs get() = _entry.extensionOIDs.toList()
    val criticalExtensionOIDs get() = _entry.criticalExtensionOIDs.toSet()
    val nonCriticalExtensionOIDs get() = _entry.nonCriticalExtensionOIDs.toSet()
}