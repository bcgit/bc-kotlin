package org.bouncycastle.kcrypto.internal

import KCryptoServices
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers
import org.bouncycastle.asn1.misc.ScryptParams
import org.bouncycastle.asn1.pkcs.KeyDerivationFunc
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.crypto.PasswordConverter
import org.bouncycastle.kcrypto.PBESymmetricKey
import org.bouncycastle.kcrypto.PBKDF
import org.bouncycastle.kcrypto.SymmetricKey
import org.bouncycastle.kcrypto.spec.KeyGenSpec
import org.bouncycastle.kcrypto.spec.kdf.ScryptSpec
import org.bouncycastle.kcrypto.spec.symmetric.AESGenSpec
import org.bouncycastle.kcrypto.spec.symmetric.HMacGenSpec

import javax.crypto.spec.SecretKeySpec

internal class ScryptPbKdf(val skdfConf: ScryptSpec, val keySpec: KeyGenSpec) : PBKDF {

    override fun symmetricKey(password: CharArray): SymmetricKey {

        val keySize : Int
        if (keySpec is AESGenSpec) {
            keySize = (keySpec.keySize + 7) / 8
        } else {
            keySize = ((keySpec as HMacGenSpec).keySize + 7) / 8
        }
        val keyLen = (keySize + 7) / 8

        val params = ScryptParams(
            skdfConf.salt,
            skdfConf.costParameter,
            skdfConf.blockSize,
            skdfConf.parallelizationParameter,
            keyLen
        )

        val key = if (KCryptoServices._provider!!.name.equals("BC")) {
            bcScrypt(password, keyLen, params)
        } else {
            fipsScrypt(password, keyLen, params)
        }

        return PBESymmetricKey(
            keySize,
            SecretKeySpec(key, "AES"),
            PKCSObjectIdentifiers.id_PBES2,
            KeyDerivationFunc(MiscObjectIdentifiers.id_scrypt, params)
        )
    }


    internal fun bcScrypt(password: CharArray, keyLen: Int, spec: ScryptParams): ByteArray {

        val scrypt = Class.forName("org.bouncycastle.crypto.generators.SCrypt")

        val method = scrypt.getMethod(
            "generate",
            ByteArray::class.java,
            ByteArray::class.java,
            Int::class.java,
            Int::class.java,
            Int::class.java,
            Int::class.java
        )

        return method.invoke(
            null,
            PasswordConverter.UTF8.convert(password),
            spec.salt,
            spec.costParameter.intValueExact(),
            spec.blockSize.intValueExact(),
            spec.parallelizationParameter.intValueExact(),
            keyLen
        ) as ByteArray
    }

    internal fun fipsScrypt(password: CharArray, keyLen: Int, spec: ScryptParams): ByteArray {

        var ksfClass: Class<*>
        var scrypt: Any
        var factory: Any

        try {
            ksfClass = Class.forName("org.bouncycastle.crypto.fips.Scrypt")
            scrypt = ksfClass.getField("ALGORITHM").get(null)
            factory = Class.forName("org.bouncycastle.crypto.fips.Scrypt\$KDFFactory").newInstance()
        } catch (e: ClassNotFoundException) {
            ksfClass = Class.forName("org.bouncycastle.crypto.general.KDF")
            scrypt = ksfClass.getField("SCRYPT").get(null)
            factory = Class.forName("org.bouncycastle.crypto.general.KDF\$SCryptFactory").newInstance()
        }

        val params = scrypt.javaClass.getMethod(
            "using",
            ByteArray::class.java,
            Int::class.java,
            Int::class.java,
            Int::class.java,
            PasswordConverter::class.java,
            CharArray::class.java
        )
            .invoke(
                scrypt,
                spec.salt,
                spec.costParameter.intValueExact(),
                spec.blockSize.intValueExact(),
                spec.parallelizationParameter.intValueExact(),
                PasswordConverter.UTF8,
                password
            )
        val res = ByteArray(keyLen)


        val kdfInt = Class.forName("org.bouncycastle.crypto.KDFCalculator")
        val calculator = factory.javaClass.getMethod("createKDFCalculator", params.javaClass).invoke(factory, params)
        val method = kdfInt.getDeclaredMethod("generateBytes", ByteArray::class.java)

        method.invoke(calculator, res)

        return res
    }


}

