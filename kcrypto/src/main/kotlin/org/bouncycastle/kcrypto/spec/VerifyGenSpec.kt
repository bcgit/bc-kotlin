package org.bouncycastle.kcrypto.spec

import org.bouncycastle.kcrypto.KeyType
import org.bouncycastle.kcrypto.VerificationKey

interface VerifyGenSpec {
    val verifyType: KeyType<VerificationKey>
}