package org.bouncycastle.kcrypto.cert.dsl

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.X500NameBuilder

fun x500Name(block: X500NameBuilder.() -> Unit): X500Name = X500NameBuilder().apply(block).build()

fun x500Name(encoded: ByteArray): X500Name = X500Name.getInstance(encoded)

fun x500Name(dn: String): X500Name = X500Name(dn)

fun X500NameBuilder.rdn(oid: ASN1ObjectIdentifier, value: String) {
    addRDN(oid, value)
}