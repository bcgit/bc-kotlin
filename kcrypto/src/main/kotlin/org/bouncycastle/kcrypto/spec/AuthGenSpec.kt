package org.bouncycastle.kcrypto.spec

import org.bouncycastle.kcrypto.AuthenticationKey
import org.bouncycastle.kcrypto.KeyType

interface AuthGenSpec {
    val authType: KeyType<AuthenticationKey>
}