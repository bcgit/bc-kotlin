package org.bouncycastle.kcrypto.spec

import org.bouncycastle.kcrypto.KeyType
import org.bouncycastle.kcrypto.SigningKey

interface SignGenSpec {
    val signType: KeyType<SigningKey>
}