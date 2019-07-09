package org.bouncycastle.kcrypto

import java.security.PrivateKey
import java.security.PublicKey

/**
 * Holds the public and private keys of an asymmetric key pair.
 */
class KeyPair(internal val publicKey: PublicKey, internal val privateKey: PrivateKey)
{
    constructor(keyPair: java.security.KeyPair): this(keyPair.public, keyPair.private)
}