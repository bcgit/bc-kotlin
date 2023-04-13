import org.bouncycastle.kcrypto.cert.dsl.*
import org.bouncycastle.kcrypto.dsl.*
import org.bouncycastle.kcrypto.dsl.signingKeyPair
import org.bouncycastle.kutil.findBCProvider
import org.bouncycastle.kutil.writePEMObject
import java.io.OutputStreamWriter
import java.io.FileWriter


using(findBCProvider())

var kp = encryptingKeyPair {
    ntru {
        parameterSet = "ntruhrss701"
    }
}


OutputStreamWriter(System.out).writePEMObject(kp.encryptionKey)
FileWriter("ntrupriv.pem").writePEMObject(kp.decryptionKey)
FileWriter("ntrupub.pem").writePEMObject(kp.encryptionKey)

