package org.bouncycastle.kcrypto

import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.spec.AlgSpec

interface UnwrappingKey {
    fun keyUnwrapper(algSpec: AlgSpec<AlgorithmIdentifier>): KeyUnwrapper<AlgorithmIdentifier>
}