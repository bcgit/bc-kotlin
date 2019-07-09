package org.bouncycastle.kcrypto

import java.io.Closeable
import java.io.OutputStream

/**
 * Instances can calculate Message Authentication Codes.
 */
interface  MacCalculator<T>: Closeable
{
  val algorithmIdentifier: T

  val stream: OutputStream

  fun mac(): ByteArray
}