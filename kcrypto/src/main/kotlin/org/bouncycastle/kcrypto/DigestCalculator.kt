package org.bouncycastle.kcrypto

import java.io.Closeable
import java.io.OutputStream

/**
 * Operator interface for a calculator of digests.
 *
 * @param T base type for the algorithm parameters
 */
interface DigestCalculator<T>: Closeable
{
  val algorithmIdentifier: T

  /**
   * Stream to write the data to be digested.
   */
  val stream: OutputStream

  /**
   * Return the digest calculated from the data written to stream.
   *
   * @return a byte array containing the digest value.
   */
  fun digest(): ByteArray
}