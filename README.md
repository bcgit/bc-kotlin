
# The Bouncy Castle Crypto Package for Kotlin

The Bouncy Castle Crypto package for Kotlin is a set of Kotlin classes designed to go on top of the Bouncy Castle Crypto Java APIs. The classes can be run with either the general BC APIs or the BC-FJA FIPS version.

Except where otherwise stated, this software is distributed under a license based on the MIT X Consortium license. To view the license, [see here](https://www.bouncycastle.org/licence.html). The BC Java OpenPGP library also includes a modified BZIP2 library which is licensed under the [Apache Software License, Version 2.0](http://www.apache.org/licenses/).

## Code Organisation

The **kcrypto** module provides the core functionality for the library.

The **examples** module provides examples of DSL use for various features, such as X.509 certificate and CRL generation, as well PKCS#10 certification requests.

The **scripts** directory contains easily modifiable kotlin scripts to generate keys and certificate chains.

## Building

The gradle script has been tested with gradle-4.9 and later.

To build put desired versions of BC jars in the directory bc-jars-reg and build with:

> gradle build

BC version 1.72b13 or later is required to build due to PQC support for Falcon and Dilithium.

## Running

Kotlin needs to be installed. 

On Ubuntu:

`sudo snap install kotlin --classic`

After that, needed kotlin libraries are added to the lib folder for you, and you can easily run the examples and scripts. Modify them and have fun.

### Scripts
Examples of running kotlin script examples:

`kotlinc -cp kcrypto/build/libs/bc-kcrypto-0.0.9.jar:bc-jars-fips/bc-fips-1.0.2.3.jar:bc-jars-fips/bcpkix-fips-1.0.6.jar -script scripts/MakeFullPath.kts`

`kotlin -cp kcrypto/build/libs/bc-kcrypto-0.0.9.jar:bc-jars-reg/bcprov-ext-jdk18on-172b13.jar:bc-jars-reg/bcpkix-jdk18on-172b13.jar:bc-jars-reg/bcutil-jdk18on-172b13.jar scripts/Falcon.kts`

You can also run kotlin interactively like:
```
kotlin -cp kcrypto/build/libs/bc-kcrypto-0.0.9.jar:bc-jars-reg/bcprov-ext-jdk18on-172b13.jar:bc-jars-reg/bcpkix-jdk18on-172b13.jar:bc-jars-reg/bcutil-jdk18on-172b13.jar
>>> :load scripts/Falcon.kts
```

# Code
How to run code examples:

Build to code (into .class files)
```
cd examples
gradle build
cd ..
```
Run 'main' methods in the examples:

`kotlin -cp kcrypto/build/libs/bc-kcrypto-0.0.9.jar:bc-jars-reg/bcprov-ext-jdk18on-172b13.jar:bc-jars-reg/bcpkix-jdk18on-172b13.jar:bc-jars-reg/bcutil-jdk18on-172b13.jar:examples/build/classes/kotlin/main MakeV3SelfSignedCertificateKt'

## Feedback and Contributions

If you want to provide feedback directly to the members of **The Legion** then please use [feedback-crypto@bouncycastle.org](mailto:feedback-crypto@bouncycastle.org), if you want to help this project survive please consider [donating](https://www.bouncycastle.org/donate) or purchasing a support contract.

For bug reporting/requests you can report issues here on github, or via feedback-crypto if required. We will accept pull requests based on this repository as well, but only on the basis that any code included may be distributed under the [Bouncy Castle License](https://www.bouncycastle.org/licence.html).

## Finally

Enjoy!
