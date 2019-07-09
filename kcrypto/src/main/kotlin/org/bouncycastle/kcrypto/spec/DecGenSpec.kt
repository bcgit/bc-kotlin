package org.bouncycastle.kcrypto.spec

import org.bouncycastle.kcrypto.DecryptionKey
import org.bouncycastle.kcrypto.KeyType

interface DecGenSpec {
    val decType: KeyType<DecryptionKey>
}