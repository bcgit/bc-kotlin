package org.bouncycastle.kcrypto.cms

import org.bouncycastle.asn1.ASN1ObjectIdentifier

interface TypedContent {

    val type: ASN1ObjectIdentifier
    val content: ByteArray?
}