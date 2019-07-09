package org.bouncycastle.kutil

/**
 * A generic interface describing a simple store of objects.
 *
 * @param T the object type stored.
 */
interface Store<T>: Collection<T> {

    /**
     * Return the single match for the passed in selector, or null if no match
     * is found. If more than one match is found a MatchNotUniqueException is thrown.
     *
     * @param selector the selector defining the match criteria.
     * @return a collection of matching objects, empty if none available.
     * @throws StoreException if there is a failure during matching.
     * @throws MatchNotUniqueException if there is a failure during matching.
     */
    @Throws(StoreException::class, MatchNotUniqueException::class)
    fun match(selector: Selector<T>): T?

    /**
     * Return a possibly empty collection of objects that match the criteria implemented
     * in the passed in Selector.
     *
     * @param selector the selector defining the match criteria.
     * @return a collection of matching objects, empty if none available.
     * @throws StoreException if there is a failure during matching.
     */
    @Throws(StoreException::class)
    fun matches(selector: Selector<T>): Collection<T>
}

/**
 * Interface a selector from a store should conform to.
 *
 * @param T the type stored in the store.
 */
interface Selector<T> {
    /**
     * Match the passed in object, returning true if it would be selected by this selector, false otherwise.
     *
     * @param obj the object to be matched.
     * @return true if the object is a match for this selector, false otherwise.
     */
    fun matches(obj: T): Boolean
}

/**
 * Exception thrown during an error on matching in a Store.
 *
 * @param msg message to be associated with this exception.
 * @param cause the throwable that caused this exception to be raised.
 */
class StoreException(msg: String, cause: Throwable?) : RuntimeException(msg, cause)

/**
 * Exception thrown during if Store.match() finds more than one match for a selector.
 *
 * @param msg message to be associated with this exception.
 */
class MatchNotUniqueException(msg: String) : RuntimeException(msg)