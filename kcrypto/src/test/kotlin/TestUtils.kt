import java.security.Provider
import java.security.Security

fun initProvider() {


    var provider = Security.getProvider("BC")
    if (provider == null) {
        provider = Security.getProvider("BCFIPS")
    }

    if (provider == null) {
        try {
            val cl1 = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider")
            provider = cl1.newInstance() as Provider
            Security.addProvider(provider)
            val cl2 = Class.forName("org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider")
            val pqcProvider = cl2.newInstance() as Provider
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

    KCryptoServices.setProvider(provider)

}