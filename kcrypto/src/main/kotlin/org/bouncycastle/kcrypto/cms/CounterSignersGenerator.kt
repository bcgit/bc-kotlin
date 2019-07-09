package org.bouncycastle.kcrypto.cms

import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.kutil.CollectionStore
import org.bouncycastle.kutil.Store

/**
 * Generator for counter signatures on an existing SignerInfo object
 */
class CounterSignersGenerator {
    private val gen = CMSSignedDataGenerator()

    fun addSignerInfoGenerator(signerInfoGenerator: SignerInfoGenerator)
    {
        gen.addSignerInfoGenerator(signerInfoGenerator.generate())
    }

    /**
     * generate a Store of one or more SignerInfo objects representing counter signatures on
     * the passed in SignerInfo object.
     *
     * @param signerInfo the signer to be countersigned
     * @return a store containing the signers.
     */
    fun generate(signerInfo: SignerInfo): Store<SignerInfo> {
        return CollectionStore(gen.generateCounterSigners(signerInfo.signerInf).map { SignerInfo(it) })
    }
}