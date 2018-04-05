# SHA3-224 DSS Implementation with Chain-Hashing

Quick implementation playing around with SHA3-224 (using BouncyCastle) hashes and digital signatures.
Also does a little bit of chain hashing mimicing blockchain hashes.

Comes with 3 classes:

1. BlockchainDSS.java

Main program. Makes the calls to the DSS and blockchain transaction modules.

2. DSSmodule.java

Implements DSS for generating signatures and verifying signatures.
SHA3-224 hash used as hashing function.

3. TransactionModule.java

Creates transactions based on blockchain concepts (chain hashing). 
Creates a pre-image for the SHA3 hash of 24 leading 0 bits for proof of work.

Warning:
Bad coding practices used - written late at night.
Not for the self respecting dev
