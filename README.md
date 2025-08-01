# crsyspqc

Package `crsyspqc` provides an interface to CryptoSys PQC for go programmers.

**CryptoSys PQC** provides Post-Quantum Cryptography algorithms as specified by NIST.
It requires **CryptoSys PQC** to be installed on your computer, available for free at
<https://www.cryptosys.net/pqc/>

This interface provides support for all parameter sets of the NIST-approved ML-KEM, ML-DSA and SLH-DSA algorithms,
with methods for .KeyGen, .Encaps, .Decaps, .Sign and .Verify.
All parameters are passed a byte arrays (except optional random test values, which are passed in hex).

References:
  - [FIPS203] Module-Lattice-based Key-Encapsulation Mechanism Standard
  - [FIPS204] Module-Lattice-Based Digital Signature Standard
  - [FIPS205] Stateless Hash-Based Digital Signature Standard

[FIPS203]: https://doi.org/10.6028/NIST.FIPS.203
[FIPS204]: https://doi.org/10.6028/NIST.FIPS.204
[FIPS205]: https://doi.org/10.6028/NIST.FIPS.205


David Ireland  
CryptoSys, Australia  
<https://www.cryptosys.net/contact/>
