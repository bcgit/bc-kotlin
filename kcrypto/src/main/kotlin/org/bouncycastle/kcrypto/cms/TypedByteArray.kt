package org.bouncycastle.kcrypto.cms

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers

class TypedByteArray(override val type: ASN1ObjectIdentifier, override val content: ByteArray) : TypedContent
{
      constructor(content: ByteArray) : this(PKCSObjectIdentifiers.data, content)

    fun typedStream(): TypedContentStream = TypedContentStream(type, content.inputStream())
}