package org.bouncycastle.kutil

import org.bouncycastle.asn1.*
import org.bouncycastle.util.Strings
import org.bouncycastle.util.encoders.Hex
import java.io.IOException
import kotlin.reflect.KVisibility

/**
 * ASN1Dump
 * @param oidMap = a map of ASN1ObjectIdentifiers -> Strings
 * @param translateOids true (default) = attempt to convert oid 1.2.3.xx to a string.
 */
class ASN1Dump(val oidMap: Map<ASN1ObjectIdentifier, String>, val translateOids: Boolean = true) {

    private val TAB = "    "
    private val SAMPLE_SIZE = 32


    companion object {

        // Classes from BCFIPS that contain oid constants.
        val bcFipsOidMapping =
            """
            org.bouncycastle.asn1.anssi.ANSSIObjectIdentifiers
            org.bouncycastle.asn1.bc.BCObjectIdentifiers
            org.bouncycastle.asn1.bsi.BSIObjectIdentifiers
            org.bouncycastle.asn1.cmp.CMPObjectIdentifiers
            org.bouncycastle.asn1.cms.CMSObjectIdentifiers
            org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers
            org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers
            org.bouncycastle.asn1.dvcs.DVCSObjectIdentifiers
            org.bouncycastle.asn1.eac.EACObjectIdentifiers
            org.bouncycastle.asn1.edec.EdECObjectIdentifiers
            org.bouncycastle.asn1.gm.GMObjectIdentifiers
            org.bouncycastle.asn1.gnu.GNUObjectIdentifiers
            org.bouncycastle.asn1.iana.IANAObjectIdentifiers
            org.bouncycastle.asn1.icao.ICAOObjectIdentifiers
            org.bouncycastle.asn1.isismtt.ISISMTTObjectIdentifiers
            org.bouncycastle.asn1.isismtt.x509.ProfessionInfo
            org.bouncycastle.asn1.iso.ISOIECObjectIdentifiers
            org.bouncycastle.asn1.kisa.KISAObjectIdentifiers
            org.bouncycastle.asn1.microsoft.MicrosoftObjectIdentifiers
            org.bouncycastle.asn1.misc.MiscObjectIdentifiers
            org.bouncycastle.asn1.nist.NISTObjectIdentifiers
            org.bouncycastle.asn1.nsri.NSRIObjectIdentifiers
            org.bouncycastle.asn1.ntt.NTTObjectIdentifiers
            org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers
            org.bouncycastle.asn1.oiw.OIWObjectIdentifiers
            org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
            org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers
            org.bouncycastle.asn1.sec.SECObjectIdentifiers
            org.bouncycastle.asn1.smime.SMIMECapabilities
            org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers
            org.bouncycastle.asn1.ua.UAObjectIdentifiers
            org.bouncycastle.asn1.x500.style.BCStyle
            org.bouncycastle.asn1.x500.style.RFC4519Style
            org.bouncycastle.asn1.x509.Extension
            org.bouncycastle.asn1.x509.PolicyQualifierId
            org.bouncycastle.asn1.x509.X509AttributeIdentifiers
            org.bouncycastle.asn1.x509.X509ObjectIdentifiers
            org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers
            org.bouncycastle.asn1.x509.qualified.RFC3739QCObjectIdentifiers
            org.bouncycastle.asn1.x509.sigi.SigIObjectIdentifiers
            org.bouncycastle.asn1.x9.X9ObjectIdentifiers
""".trimIndent().split("\n").fold(mutableMapOf<ASN1ObjectIdentifier, String>()) {

                    a, b ->
                try {
                    val holder = Class.forName(b.trim().toString()).kotlin
                    holder.members.forEach {
                        if (it.visibility == KVisibility.PUBLIC && it.parameters.isEmpty()) {
                            if (it.returnType.toString().contains("ASN1ObjectIdentifier")) {
                                val name =
                                    if (holder.simpleName != null) holder.simpleName + "." + it.name else "" + it.name
                                a.put(it.call() as ASN1ObjectIdentifier, name)
                            }
                        }
                    }
                } catch (th: Throwable) {
                    // Scanning is on a best effort basis.
                }

                a
            }


        /**
         * Resolve a single oid.
         */
        fun resolveOid(
            oid: ASN1ObjectIdentifier,
            oidMap: Map<ASN1ObjectIdentifier, String> = bcFipsOidMapping
        ): String = ASN1Dump(oidMap, true).resolveOid(oid)


        /**
         * dump out a DER object as a formatted string, in non-verbose mode.
         *
         * @param obj the ASN1Primitive to be dumped out.
         * @return  the resulting string.
         */
        fun dumpAsString(
            obj: Any
        ): String {
            return dumpAsString(obj, bcFipsOidMapping)
        }

        /**
         * Dump out the object as a string.
         *
         * @param obj  the object to be dumped
         * @param verbose  if true, dump out the contents of octet and bit strings.
         * @return  the resulting string.
         */
        fun dumpAsString(
            obj: Any,
            oidMap: Map<ASN1ObjectIdentifier, String> = bcFipsOidMapping,
            translateOids: Boolean = true,
            verbose: Boolean = false
        ): String {

            return ASN1Dump(oidMap, translateOids).dumpAsString(obj, verbose)

        }


    } // -- companion object


    fun resolveOid(oid: ASN1ObjectIdentifier): String =
        if (!translateOids) oid.toString() else oidMap[oid] ?: oid.toString()


    /**
     * dump a DER object as a formatted string with indentation
     *
     * @param obj the ASN1Primitive to be dumped out.
     */
    internal fun _dumpAsString(
        indent: String,
        verbose: Boolean,
        obj: ASN1Primitive,
        buf: StringBuffer
    ) {
        val nl = Strings.lineSeparator()
        if (obj is ASN1Sequence) {
            val e = obj.objects
            val tab = indent + TAB

            buf.append(indent)
            if (obj is BERSequence) {
                buf.append("BER Sequence")
            } else if (obj is DERSequence) {
                buf.append("DER Sequence")
            } else {
                buf.append("Sequence")
            }

            buf.append(nl)

            while (e.hasMoreElements()) {
                val o = e.nextElement()

                if (o == null || o == DERNull.INSTANCE) {
                    buf.append(tab)
                    buf.append("NULL")
                    buf.append(nl)
                } else if (o is ASN1Primitive) {
                    _dumpAsString(tab, verbose, o, buf)
                } else {
                    _dumpAsString(tab, verbose, (o as ASN1Encodable).toASN1Primitive(), buf)
                }
            }
        } else if (obj is ASN1TaggedObject) {
            val tab = indent + TAB

            buf.append(indent)
            if (obj is BERTaggedObject) {
                buf.append("BER Tagged [")
            } else {
                buf.append("Tagged [")
            }

            buf.append(Integer.toString(obj.tagNo))
            buf.append(']')

            if (!obj.isExplicit) {
                buf.append(" IMPLICIT ")
            }

            buf.append(nl)

            if (obj.getBaseObject() == null) {
                buf.append(tab)
                buf.append("EMPTY")
                buf.append(nl)
            } else {
                _dumpAsString(tab, verbose, obj.getBaseObject().toASN1Primitive(), buf)
            }
        } else if (obj is ASN1Set) {
            val e = obj.objects
            val tab = indent + TAB

            buf.append(indent)

            if (obj is BERSet) {
                buf.append("BER Set")
            } else if (obj is DERSet) {
                buf.append("DER Set")
            } else {
                buf.append("Set")
            }
            buf.append(nl)

            while (e.hasMoreElements()) {
                val o = e.nextElement()

                if (o == null) {
                    buf.append(tab)
                    buf.append("NULL")
                    buf.append(nl)
                } else if (o is ASN1Primitive) {
                    _dumpAsString(tab, verbose, o, buf)
                } else {
                    _dumpAsString(tab, verbose, (o as ASN1Encodable).toASN1Primitive(), buf)
                }
            }
        } else if (obj is ASN1OctetString) {

            if (obj is BEROctetString) {
                buf.append(indent + "BER Constructed Octet String" + "[" + obj.octets.size + "] ")
            } else {
                buf.append(indent + "DER Octet String" + "[" + obj.octets.size + "] ")
            }
            if (verbose) {
                buf.append(dumpBinaryDataAsString(indent, obj.octets))
            } else {
                buf.append(nl)
            }
        } else if (obj is ASN1ObjectIdentifier) {
            buf.append(indent + "ObjectIdentifier(" + resolveOid(obj) + ")" + nl)
        } else if (obj is ASN1Boolean) {
            buf.append(indent + "Boolean(" + obj.isTrue + ")" + nl)
        } else if (obj is ASN1Integer) {
            buf.append(indent + "Integer(" + obj.value + ")" + nl)
        } else if (obj is DERBitString) {
            buf.append(indent + "DER Bit String" + "[" + obj.bytes.size + ", " + obj.padBits + "] ")
            if (verbose) {
                buf.append(dumpBinaryDataAsString(indent, obj.bytes))
            } else {
                buf.append(nl)
            }
        } else if (obj is DERIA5String) {
            buf.append(indent + "IA5String(" + obj.string + ") " + nl)
        } else if (obj is DERUTF8String) {
            buf.append(indent + "UTF8String(" + obj.string + ") " + nl)
        } else if (obj is DERPrintableString) {
            buf.append(indent + "PrintableString(" + obj.string + ") " + nl)
        } else if (obj is DERVisibleString) {
            buf.append(indent + "VisibleString(" + obj.string + ") " + nl)
        } else if (obj is DERBMPString) {
            buf.append(indent + "BMPString(" + obj.string + ") " + nl)
        } else if (obj is DERT61String) {
            buf.append(indent + "T61String(" + obj.string + ") " + nl)
        } else if (obj is DERGraphicString) {
            buf.append(indent + "GraphicString(" + obj.string + ") " + nl)
        } else if (obj is DERVideotexString) {
            buf.append(indent + "VideotexString(" + obj.string + ") " + nl)
        } else if (obj is ASN1UTCTime) {
            buf.append(indent + "UTCTime(" + obj.time + ") " + nl)
        } else if (obj is ASN1GeneralizedTime) {
            buf.append(indent + "GeneralizedTime(" + obj.time + ") " + nl)
        } else if (obj is BERApplicationSpecific) {
            buf.append(outputApplicationSpecific("BER", indent, verbose, obj, nl))
        } else if (obj is DERApplicationSpecific) {
            buf.append(outputApplicationSpecific("DER", indent, verbose, obj, nl))
        } else if (obj is DLApplicationSpecific) {
            buf.append(outputApplicationSpecific("", indent, verbose, obj, nl))
        } else if (obj is ASN1Enumerated) {
            buf.append(indent + "DER Enumerated(" + obj.value + ")" + nl)
        } else if (obj is ASN1External) {
            buf.append(indent + "External " + nl)
            val tab = indent + TAB
            if (obj.directReference != null) {
                buf.append(tab + "Direct Reference: " + obj.directReference.id + nl)
            }
            if (obj.indirectReference != null) {
                buf.append(tab + "Indirect Reference: " + obj.indirectReference.toString() + nl)
            }
            if (obj.dataValueDescriptor != null) {
                _dumpAsString(tab, verbose, obj.dataValueDescriptor, buf)
            }
            buf.append(tab + "Encoding: " + obj.encoding + nl)
            _dumpAsString(tab, verbose, obj.externalContent, buf)
        } else {
            buf.append(indent + obj.toString() + nl)
        }
    }

    private fun outputApplicationSpecific(
        type: String,
        indent: String,
        verbose: Boolean,
        obj: ASN1Primitive,
        nl: String
    ): String {
        val app = ASN1ApplicationSpecific.getInstance(obj)
        val buf = StringBuffer()

        if (app.isConstructed) {
            try {
                val s = ASN1Sequence.getInstance(app.getObject(BERTags.SEQUENCE))
                buf.append(indent + type + " ApplicationSpecific[" + app.applicationTag + "]" + nl)
                val e = s.objects
                while (e.hasMoreElements()) {
                    _dumpAsString(indent + TAB, verbose, e.nextElement() as ASN1Primitive, buf)
                }
            } catch (e: IOException) {
                buf.append(e)
            }

            return buf.toString()
        }

        return indent + type + " ApplicationSpecific[" + app.applicationTag + "] (" + Strings.fromByteArray(
            Hex.encode(
                app.contents
            )
        ) + ")" + nl
    }

    /**
     * dump out a DER object as a formatted string, in non-verbose mode.
     *
     * @param obj the ASN1Primitive to be dumped out.
     * @return  the resulting string.
     */
    fun dumpAsString(
        obj: Any
    ): String {
        return dumpAsString(obj, false)
    }

    /**
     * Dump out the object as a string.
     *
     * @param obj  the object to be dumped
     * @param verbose  if true, dump out the contents of octet and bit strings.
     * @return  the resulting string.
     */
    fun dumpAsString(
        obj: Any,
        verbose: Boolean
    ): String {
        val buf = StringBuffer()

        if (obj is ASN1Primitive) {
            _dumpAsString("", verbose, obj, buf)
        } else if (obj is ASN1Encodable) {
            _dumpAsString("", verbose, obj.toASN1Primitive(), buf)
        } else {
            return "unknown object type $obj"
        }

        return buf.toString()
    }

    private fun dumpBinaryDataAsString(indent: String, bytes: ByteArray): String {
        var indent = indent
        val nl = Strings.lineSeparator()
        val buf = StringBuffer()

        indent += TAB

        buf.append(nl)
        var i = 0
        while (i < bytes.size) {
            if (bytes.size - i > SAMPLE_SIZE) {
                buf.append(indent)
                buf.append(Strings.fromByteArray(Hex.encode(bytes, i, SAMPLE_SIZE)))
                buf.append(TAB)
                buf.append(calculateAscString(bytes, i, SAMPLE_SIZE))
                buf.append(nl)
            } else {
                buf.append(indent)
                buf.append(Strings.fromByteArray(Hex.encode(bytes, i, bytes.size - i)))
                for (j in bytes.size - i until SAMPLE_SIZE) {
                    buf.append("  ")
                }
                buf.append(TAB)
                buf.append(calculateAscString(bytes, i, bytes.size - i))
                buf.append(nl)
            }
            i += SAMPLE_SIZE
        }

        return buf.toString()
    }

    private fun calculateAscString(bytes: ByteArray, off: Int, len: Int): String {
        val buf = StringBuffer()

        for (i in off until off + len) {
            if (bytes[i] >= ' '.toByte() && bytes[i] <= '~'.toByte()) {
                buf.append(bytes[i].toChar())
            }
        }

        return buf.toString()
    }
}
