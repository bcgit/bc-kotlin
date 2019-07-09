package org.bouncycastle.kutil

class CollectionStore<T>(private val baseCollection: Collection<T>) : Store<T> {

    constructor(vararg elements: T): this(elements.asList())

    override fun match(selector: Selector<T>): T? {

        var col = matches(selector)

        if (col.isEmpty()) {
            return null
        }
        if (col.size != 1) {
            throw MatchNotUniqueException(col.size.toString() + " matches found for selector")
        }

        return col.first()
    }

    override fun matches(selector: Selector<T>): Collection<T> {

        return baseCollection.filter { selector.matches(it) }
    }

    override val size: Int
        get() = baseCollection.size

    override fun contains(element: T): Boolean {
        return baseCollection.contains(element)
    }

    override fun containsAll(elements: Collection<T>): Boolean {
        return baseCollection.containsAll(elements)
    }

    override fun isEmpty(): Boolean {
        return baseCollection.isEmpty()
    }

    override fun iterator(): Iterator<T> {
        return baseCollection.iterator()
    }
}