package org.bouncycastle.kcrypto.spec

/**
 * Base interface for an algorithm specification.
 */
interface AlgSpec<T>
{
    /**
     * Object providing the specifics for identifying an algorithm.
     */
    val algorithmIdentifier: T
}