package org.bouncycastle.kcrypto

import java.io.Closeable
import java.io.OutputStream

interface SignatureCalculator<T>: Closeable
{
  val algorithmIdentifier: T

  val stream: OutputStream

  fun signature(): ByteArray
}