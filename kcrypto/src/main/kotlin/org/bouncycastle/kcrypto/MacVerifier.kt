package org.bouncycastle.kcrypto

import java.io.Closeable
import java.io.OutputStream

/**
 *
 */
interface MacVerifier<T>: Closeable
{
  val algorithmIdentifier: T

  val stream: OutputStream

  fun verifies(expected: ByteArray): Boolean
}