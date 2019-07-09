package org.bouncycastle.kcrypto.cms

/**
 * Property names for values appearing in the tables passed to the attribute table generation blocks.
 * <p>
 * Note: The SIGNATURE parameter is only available when generating unsigned attributes.
 */
class AttributeTableProperties {

    companion object {
        val CONTENT_TYPE = "contentType"
        val DIGEST = "digest"
        val SIGNATURE = "encryptedDigest"
        val DIGEST_ALGORITHM_IDENTIFIER = "digestAlgID"
        val MAC_ALGORITHM_IDENTIFIER = "macAlgID"
        val SIGNATURE_ALGORITHM_IDENTIFIER = "signatureAlgID"
    }
}