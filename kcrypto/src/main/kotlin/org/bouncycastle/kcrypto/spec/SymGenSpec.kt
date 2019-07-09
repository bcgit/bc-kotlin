package org.bouncycastle.kcrypto.spec

import org.bouncycastle.kcrypto.KeyType
import org.bouncycastle.kcrypto.SymmetricKey

interface SymGenSpec {
    val symType: KeyType<SymmetricKey>
}
