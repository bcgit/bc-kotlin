package org.bouncycastle.kcrypto

interface IndexedSignatureCalculator<T>: SignatureCalculator<T>
{
  fun index(): Long
}