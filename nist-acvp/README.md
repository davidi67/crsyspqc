Run the NIST-ACVP tests for PQC using CryptoSys PQC
===================================================

These tests validate against the PQC NIST-ACVP tests at https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files.

There are 8 tests written in go. The tests look for JSON files in the data directory.

For example, if `mldsa-keygen.go` is called from VsCode it will look for the json data file
`ML-DSA-keyGen-FIPS204-1_1_0_39.json` in `..\data\`.

If called from this directory

    go run mldsa-keygen/mldsa-keygen.go
	
then it will look for the json file in `.\data\`.

The Windows batch file `do-acvp-tests.bat` will call all these go files in turn.
By default, it will not call `slhdsa-siggen.go` because this takes several minutes to run.

	slhdsa-siggen.go OMITTED FOR TIME CONSTRAINTS
	To run type ``do-acvp-tests -doshlsig``

```text
crsyspqc\nist-acvp
|   do-acvp-tests.bat
|   main.go
|
+---data
|       ML-DSA-keyGen-FIPS204-1_1_0_39.json
|       ML-DSA-sigGen-FIPS204-1_1_0_39.json
|       ML-DSA-sigGen-preHashes-1_1_0_39.json
|       ML-DSA-sigVer-FIPS204-1_1_0_39.json
|       ML-DSA-sigVer-preHashes-1_1_0_39.json
|       ML-KEM-encapDecap-FIPS203-1_1_0_39.json
|       ML-KEM-keyGen-FIPS203-1_1_0_39.json
|       README.md
|       SLH-DSA-keyGen-FIPS205-1_1_0_38.json
|       SLH-DSA-sigGen-FIPS205-1_1_0_38.json
|       SLH-DSA-sigGen-preHashes-1_1_0_38.json
|       SLH-DSA-sigVer-FIPS205-1_1_0_38.json
|       SLH-DSA-sigVer-preHashes-1_1_0_38.json
|
+---mldsa-keygen
|       mldsa-keygen.go
|
+---mldsa-siggen
|       mldsa-siggen.go
|
+---mldsa-sigver
|       mldsa-sigver.go
|
+---mlkem-encap-decap
|       mlkem-encap-decap.go
|
+---mlkem-keygen
|       mlkem-keygen.go
|
+---slhdsa-keygen
|       slhdsa-keygen.go
|
+---slhdsa-siggen
|       slhdsa-siggen.go
|
\---slhdsa-sigver
        slhdsa-sigver.go
```
