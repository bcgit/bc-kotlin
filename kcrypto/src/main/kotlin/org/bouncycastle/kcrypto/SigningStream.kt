package org.bouncycastle.kcrypto

import java.io.IOException
import java.io.OutputStream
import java.security.Signature

internal class SigningStream internal constructor(private val sig: Signature) : OutputStream() {

    private var isClosed: Boolean = false

    internal val signature: ByteArray
        get() {
            if (!isClosed) {
                throw IllegalStateException("attempt to call signature() without closing stream")
            }
            return sig.sign()
        }

    @Throws(IOException::class)
    override fun write(bytes: ByteArray, off: Int, len: Int) {
        sig.update(bytes, off, len)
    }

    @Throws(IOException::class)
    override fun write(bytes: ByteArray) {
        sig.update(bytes)
    }

    @Throws(IOException::class)
    override fun write(b: Int) {
        sig.update(b.toByte())
    }

    @Throws(IOException::class)
    override fun close() {
        super.close()
        isClosed = true
    }
}
