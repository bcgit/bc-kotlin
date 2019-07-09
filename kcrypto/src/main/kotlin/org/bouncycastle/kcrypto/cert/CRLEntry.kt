package org.bouncycastle.kcrypto.cert

import org.bouncycastle.cert.X509CRLEntryHolder
import java.math.BigInteger

class CRLEntry {
    private val _entry: X509CRLEntryHolder

    internal constructor(entry: X509CRLEntryHolder) {
        _entry = entry
    }

    val serialNumber: BigInteger get() = _entry.serialNumber
    val extensions get() = _entry.extensions
}