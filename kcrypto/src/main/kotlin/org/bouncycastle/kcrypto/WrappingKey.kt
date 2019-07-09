package org.bouncycastle.kcrypto

import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.spec.AlgSpec

interface WrappingKey
{
    fun keyWrapper(algSpec: AlgSpec<AlgorithmIdentifier>): KeyWrapper<AlgorithmIdentifier>
}