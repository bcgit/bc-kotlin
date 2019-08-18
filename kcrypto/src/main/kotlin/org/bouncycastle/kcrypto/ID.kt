package org.bouncycastle.kcrypto

import org.bouncycastle.util.Strings

class ID(val identifier: ByteArray) {
    constructor(identifier: String) : this(Strings.toUTF8ByteArray(identifier))
}