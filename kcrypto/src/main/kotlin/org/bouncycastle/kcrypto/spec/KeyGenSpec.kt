package org.bouncycastle.kcrypto.spec

import java.security.SecureRandom

/**
 * Defines parameters for specific key generation algorithms.
 */
interface KeyGenSpec
{
    val random: SecureRandom
}