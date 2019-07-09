package org.bouncycastle.kcrypto

interface PBKDF
{
    fun symmetricKey(password: CharArray): SymmetricKey
}