package org.bouncycastle.kcrypto.cmp

import org.bouncycastle.kcrypto.Encodable

class ProtectedPKIMessage(private val protMessage: org.bouncycastle.cert.cmp.ProtectedPKIMessage): Encodable {

    override val encoding: ByteArray
        get() = protMessage.toASN1Structure().encoded
}