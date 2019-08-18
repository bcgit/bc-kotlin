package org.bouncycastle.kcrypto

import java.security.spec.AlgorithmParameterSpec

fun convert(id: ID): AlgorithmParameterSpec
{
    var clz = Class.forName("org.bouncycastle.jcajce.spec.SM2ParameterSpec")

    return clz.getConstructor(ByteArray::class.java).newInstance(id.identifier) as AlgorithmParameterSpec
}