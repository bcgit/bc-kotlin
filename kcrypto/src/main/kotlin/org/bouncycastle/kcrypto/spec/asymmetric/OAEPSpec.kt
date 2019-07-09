package org.bouncycastle.kcrypto.spec.asymmetric

import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.kcrypto.Digest
import org.bouncycastle.kcrypto.spec.AlgSpec

/**
 * OAEP (RSA) specification
 */
class OAEPSpec(val digest: Digest): AlgSpec<AlgorithmIdentifier>
{
    override val algorithmIdentifier: AlgorithmIdentifier
        get() = TODO("not implemented") //To change initializer of created properties use File | Settings | File Templates.

}