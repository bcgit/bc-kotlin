package org.bouncycastle.kcrypto.cert

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
    val extensions get() = _entry.extensions
}