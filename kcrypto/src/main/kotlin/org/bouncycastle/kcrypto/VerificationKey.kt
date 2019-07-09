package org.bouncycastle.kcrypto

import KCryptoServices
import KCryptoServices.Companion.helper
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator
import org.bouncycastle.kcrypto.cert.Certificate
import org.bouncycastle.kcrypto.spec.SigAlgSpec
import org.bouncycastle.operator.DefaultAlgorithmNameFinder
import java.io.OutputStream
import java.security.AlgorithmParameters
import java.security.PublicKey
import java.security.Signature
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.X509EncodedKeySpec

private class VerifierProvider {

    private val pubKey: PublicKey
    private val finder = DefaultAlgorithmNameFinder()

    constructor(key: BaseVerificationKey) {
        pubKey = key._pubKey
    }

    fun get(verifierAlgorithmIdentifier: AlgorithmIdentifier): SignatureVerifier<AlgorithmIdentifier> {

        if (verifierAlgorithmIdentifier.algorithm.equals(PKCSObjectIdentifiers.id_RSASSA_PSS)) {
            // work around FIPS bug
            return Verifier(DefaultCMSSignatureAlgorithmNameGenerator().getSignatureName(
                    RSASSAPSSparams.getInstance(verifierAlgorithmIdentifier.parameters).hashAlgorithm, verifierAlgorithmIdentifier),
                        verifierAlgorithmIdentifier, pubKey)
        } else {
            return Verifier(finder.getAlgorithmName(verifierAlgorithmIdentifier), verifierAlgorithmIdentifier, pubKey)
        }
    }
}

private class Verifier(algorithm: String, algorithmIdentifier: AlgorithmIdentifier, pubKey: PublicKey) : SignatureVerifier<AlgorithmIdentifier> {

    override val stream: OutputStream
    override val algorithmIdentifier: AlgorithmIdentifier

    val sig: Signature

    init {
        sig = helper.createSignature(algorithm)

        var params = algorithmIdentifier.parameters
        if (params != null && !params.equals(DERNull.INSTANCE)) {
            var algP = AlgorithmParameters.getInstance(algorithmIdentifier.algorithm.id, KCryptoServices._provider)
            algP.init(params.toASN1Primitive().encoded)
            sig.setParameter(algP.getParameterSpec(AlgorithmParameterSpec::class.java))
        }
        sig.initVerify(pubKey)

        stream = SignatureVerificationStream(sig)

        this.algorithmIdentifier = algorithmIdentifier
    }

    override fun verifies(expected: ByteArray): Boolean {
        return (stream as SignatureVerificationStream).verify(expected)
    }

    override fun close() {
        stream.close()
    }
}

internal class BaseVerificationKey: VerificationKey {

    internal val _pubKey: PublicKey
    private val cert: Certificate?
    
    constructor(key: PublicKey)
    {
        this._pubKey = key
        this.cert = null;
    }

    constructor(cert: Certificate)
    {
        var algId = cert.subjectPublicKeyInfo.algorithm.algorithm
        this._pubKey = KCryptoServices.helper.createKeyFactory(algId.id).generatePublic(X509EncodedKeySpec(cert.subjectPublicKeyInfo.encoded))
        this.cert = cert;
    }

    override val encoding: ByteArray
        get() = _pubKey.encoded

    override fun hasAssociatedCertificate(): Boolean {
        return cert != null
    }

    override fun signatureVerifier(sigAlgSpec: SigAlgSpec): SignatureVerifier<AlgorithmIdentifier> {
        return VerifierProvider(this).get(sigAlgSpec.validatedSpec(this).algorithmIdentifier)
    }
}

interface VerificationKey: org.bouncycastle.kcrypto.PublicKey {

    fun hasAssociatedCertificate(): Boolean

    fun signatureVerifier(sigAlgSpec: SigAlgSpec): SignatureVerifier<AlgorithmIdentifier>
}
