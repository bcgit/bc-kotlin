package org.bouncycastle.kcrypto.spec

import org.bouncycastle.kcrypto.EncryptionKey
import org.bouncycastle.kcrypto.KeyType

interface EncGenSpec {
    val encType: KeyType<EncryptionKey>
}