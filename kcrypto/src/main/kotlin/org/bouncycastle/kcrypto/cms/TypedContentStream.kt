package org.bouncycastle.kcrypto.cms

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.util.io.Streams
import java.io.IOException
import java.io.InputStream

class TypedContentStream(val type: ASN1ObjectIdentifier, val stream: InputStream) {

    @Throws(IOException::class)
    fun drain() {
        Streams.drain(stream)
        this.stream.close()
    }
}