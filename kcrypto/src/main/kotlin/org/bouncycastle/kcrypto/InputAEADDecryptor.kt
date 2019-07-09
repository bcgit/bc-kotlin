package org.bouncycastle.kcrypto

/**
 * Decrypts an input encrypted using the Authenticated Encryption with Associated Data
 * encryption scheme.
 */
interface InputAEADDecryptor<T> : InputDecryptor<T>, AADProcessor {

}