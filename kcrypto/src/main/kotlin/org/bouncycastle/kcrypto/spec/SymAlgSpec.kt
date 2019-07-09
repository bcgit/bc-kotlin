package org.bouncycastle.kcrypto.spec

import org.bouncycastle.kcrypto.SymmetricKey

interface SymAlgSpec<T>: AlgSpec<T>
{
    fun validatedSpec(key: SymmetricKey): SymAlgSpec<T>
}