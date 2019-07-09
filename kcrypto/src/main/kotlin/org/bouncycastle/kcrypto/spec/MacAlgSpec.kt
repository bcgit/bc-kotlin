package org.bouncycastle.kcrypto.spec

import org.bouncycastle.kcrypto.AuthenticationKey

interface MacAlgSpec<T>: AlgSpec<T> {

    fun validatedSpec(key: AuthenticationKey): MacAlgSpec<T>

}