package org.bouncycastle.kutil

import java.security.Provider
import java.security.Security

fun isFIPS(): Boolean {
    return  Security.getProvider("BCFIPS") != null
}

fun findBCProvider(): Provider {
    var provider = Security.getProvider("BC")
    if (provider == null) {
        provider = Security.getProvider("BCFIPS")
    } else {
        if (Security.getProvider("BCPQC") == null) {
            val pqcCl = Class.forName("org.bouncycastle.jcajce.provider.BouncyCastlePQCProvider")
            val pqcProvider = pqcCl.newInstance() as Provider
            Security.addProvider(pqcProvider)
        }
    }

    if (provider == null) {
        try {
            val cl = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider")
            provider = cl.newInstance() as Provider
            Security.addProvider(provider)
            val pqcCl = Class.forName("org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider")
            val pqcProvider = pqcCl.newInstance() as Provider
            Security.addProvider(pqcProvider)
        } catch (ex: ClassNotFoundException) {
            val cl = Class.forName("org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider")
            provider = cl.newInstance() as Provider
            Security.addProvider(provider)
        }
    }

    if (provider == null) {
        throw IllegalStateException("Could not find either BC or BCFIPS providers on classpath.")
    }
    return provider
}
