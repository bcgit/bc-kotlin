package org.bouncycastle.kcrypto.pkcs.dsl

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.kcrypto.VerificationKey
import org.bouncycastle.kcrypto.dsl.SignatureBlock
import org.bouncycastle.kcrypto.pkcs.PKCS10Request
import java.util.*


/**
 * DSL body for defining a pkcs10 cert request
 */
class PKCS10Body
{
    lateinit var subject: X500Name
    lateinit var subjectKey: Any

    var attributes: AttributesBody? = null

    private val signature = SignatureBlock()

    fun build(): PKCS10Request {

        var builder = signature.pkcs10RequestBuilder(subject, subjectKey as VerificationKey)

        var attrElements = attributes?.elements
        if (attrElements != null) {
            for (e in attrElements) {
                builder.addAttribute(e.attrType, e.attrValue)
            }
        }

        return builder.build()
    }

    fun signature(block: SignatureBlock.()-> Unit) = signature.apply(block)
}

/**
 * DLS for creating a pkcs10Request
 */
fun pkcs10Request(block: PKCS10Body.()-> Unit): PKCS10Request = PKCS10Body().apply(block).build()

/**
 * DSL body to define attributes for the request.
 */
class AttributesBody
{
    internal val elements: MutableList<AttributeElement> = ArrayList<AttributeElement>()

    fun addAttribute(e: AttributeElement)
    {
        elements.add(e)
    }
}

/**
 * creates an attributes body block.
 */
fun attributes(block: AttributesBody.() -> Unit): AttributesBody = AttributesBody().apply(block)

/**
 * Creates an attribute block and post initialization adds that block to the AttributeBody
 */
fun AttributesBody.attribute(block: AttributeElement.() -> Unit)
{
    val e = AttributeElement(false).apply(block)
    addAttribute(e)
}

/**
 * Data class for defining an Attribute element.
 */
data class AttributeElement(var notSet: Boolean)
{
    lateinit var attrType: ASN1ObjectIdentifier
    lateinit var attrValue: ASN1Encodable
}


