import java.security.Provider
import java.security.Security

fun findBCProvider(): Provider {
    var provider = Security.getProvider("BC")
    if (provider == null) {
        provider = Security.getProvider("BCFIPS")
    }

    if (provider == null) {
        try {
            val cl = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider")
            provider = cl.newInstance() as Provider
            Security.addProvider(provider)
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
