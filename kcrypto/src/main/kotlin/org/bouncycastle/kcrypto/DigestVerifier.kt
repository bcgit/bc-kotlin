package org.bouncycastle.kcrypto

import java.io.OutputStream

/**
 * Operator interface for a verifier of digests.
 *
 * @param T base type for the algorithm parameters
 */
interface DigestVerifier<T>
{
  val algorithmIdentifier: T

  val stream: OutputStream

  fun verify(expected: ByteArray): Boolean
}