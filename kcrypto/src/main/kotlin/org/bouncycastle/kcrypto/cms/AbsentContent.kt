package org.bouncycastle.kcrypto.cms

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers

/**
 * a class representing null or absent content.
 */
class AbsentContent(override val type: ASN1ObjectIdentifier = CMSObjectIdentifiers.data) : TypedContent {

    override val content = null
}