# Adding a Signature Algorithm

## Flagging PQC algorithms

The method isPQC in KCryptoServices.kt is used to identify post quantum algorithms as these rely on the BCPQC provider rather than the BC provider. If you're adding a post quantum algorithm this method needs to be updated to recognise both the OIDs and the algorithm name for the new algorithm.

## Generating the key pair

For a signature algorithm the generation code should read something like

```
        var kp = signingKeyPair {
            <algorithm> {
                <parameters> = ...
            }
        }
```

where <algorithm> is the algorithm name type and <parameters> is the set of parameters to be set.

The signingKeyPair takes a SigningKeyBuilder - this class is defined in the KCryptoServicesDsl.kt source file.

After the initial definition of the class you will find variants on it for algorithms like RSA, DSA, etc.. To add the new algorithm you need to add a variant after the existing ones like:

```
fun SigningKeyBuilder.<algorithm>(block: <algorithm>Params.() -> Unit) {
    val p = <algorithm>Params().apply(block)

    setSpec(<algorithm>GenSpec(p.<parameters>, KCryptoServices.secureRandom))
}
```

Add the data class for <algorithm>Params to the end of the file with the others.

The <algorithm>GenSpec class should be added to the org.bouncycastle.kcrypto.spec.asymmetric package, copy one of the previous classes adjusting the constructor for your new algorithm and change the companion object definitions to use the correct algorithm name, as in:

```
    companion object: SignGenSpec, VerifyGenSpec {
        override val signType = KeyType.SIGNING.forAlgorithm("<algorithm>")
        override val verifyType = KeyType.VERIFICATION.forAlgorithm("<algorithm>")
    }
```

Next you'll need to add handling of <algorithm>GenSpec to the signingKeyPair function in KCryptoServicesDsl.kt, being careful to use the PQC helper if needed.

# Adding the Signature algorithm

Add a <algorithm>SigSpec class the org.bouncycastle.kcrypto.spec.asymmetric package using an earlier one as an example.

## Signature Generation

For generation, the SigAlgSpec class is handled in BaseSigner which is in SigningKey.kt, you need to add handling of the new <algorithm>SigSpec class to the init clause, again flagging the algorithm as PQC if required to make sure the right provider is used further on.

## Signature Verification

For verification, the SigAlgSpec class is handled in BaseSigner which is in SigningKey.kt, you need to add handling of the new <algorithm>SigSpec class to the init clause, again flagging the algorithm as PQC if required to make sure the right provider is used further on.

## Adding to DSL

In order to use the new algorithm in a script it needs to be added to the DSL classes. These live in org.bouncycastle.kcrypto.dsl - the certificate and PKCS10 generation templates use the SignatureDsl code.

There's two steps - add <algorithm> as a constant in the SignatureBlock and then add an class <algorithm>SigType to the SigType definitions lower in the file. If the signature algorithm does not require a message digest (like Ed448) the
SigType class should extend NoDigSigType rather than DigSigType.
