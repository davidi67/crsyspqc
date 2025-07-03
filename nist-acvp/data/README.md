NIST ACVP KAT FILES FOR PQC
===========================

This directory contains the following 8 files downloaded on 2025-04-29 from  
https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files

	ML-DSA-keyGen-FIPS204-1_1_0_39.json
	ML-DSA-sigGen-FIPS204-1_1_0_39.json
	ML-DSA-sigVer-FIPS204-1_1_0_39.json
	ML-KEM-encapDecap-FIPS203-1_1_0_39.json
	ML-KEM-keyGen-FIPS203-1_1_0_39.json
	SLH-DSA-keyGen-FIPS205-1_1_0_38.json
	SLH-DSA-sigGen-FIPS205-1_1_0_38.json
	SLH-DSA-sigVer-FIPS205-1_1_0_38.json
	
These are the downloads of the file `internalProjection.json` from the 
relevant Github directory.

See the [NIST licence details](#nist-license) below applicable to the above files.

It also contains the following 4 files

	ML-DSA-sigGen-preHashes-1_1_0_39.json
	SLH-DSA-sigGen-preHashes-1_1_0_38.json
	ML-DSA-sigVer-preHashes-1_1_0_39.json
	SLH-DSA-sigVer-preHashes-1_1_0_38.json

which contain computed prehash values over the message `ph=H(M)` for the DSA-sigGen/sigVer examples that use the "pre-hash" version to sign.

Use these files in the tests for **CryptoSys PQC** that access the NIST json files directly.  
http://www.cryptosys.net/pqc/

David Ireland  
DI Management Services Pty Ltd t/a CryptoSys  
http://www.cryptosys.net/


## NIST LICENSE

NIST-developed software is provided by NIST as a public service. You may use, 
copy, and distribute copies of the software in any medium, provided that you 
keep intact this entire notice. You may improve, modify, and create derivative 
works of the software or any portion of the software, and you may copy and 
distribute such modifications or works. Modified works should carry a notice 
stating that you changed the software and should note the date and nature of 
any such change. Please explicitly acknowledge the National Institute of 
Standards and Technology as the source of the software.

NIST-developed software is expressly provided "AS IS." NIST MAKES NO WARRANTY 
OF ANY KIND, EXPRESS, IMPLIED, IN FACT, OR ARISING BY OPERATION OF LAW, 
INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS 
FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, AND DATA ACCURACY. NIST NEITHER 
REPRESENTS NOR WARRANTS THAT THE OPERATION OF THE SOFTWARE WILL BE UNINTERRUPTED
OR ERROR-FREE, OR THAT ANY DEFECTS WILL BE CORRECTED. NIST DOES NOT WARRANT OR 
MAKE ANY REPRESENTATIONS REGARDING THE USE OF THE SOFTWARE OR THE RESULTS 
THEREOF, INCLUDING BUT NOT LIMITED TO THE CORRECTNESS, ACCURACY, RELIABILITY, 
OR USEFULNESS OF THE SOFTWARE.

You are solely responsible for determining the appropriateness of using and 
distributing the software and you assume all risks associated with its use, 
including but not limited to the risks and costs of program errors, compliance 
with applicable laws, damage to or loss of data, programs or equipment, and the 
unavailability or interruption of operation. This software is not intended to 
be used in any situation where a failure could cause risk of injury or damage 
to property. The software developed by NIST employees is not subject to 
copyright protection within the United States.

Ref: https://github.com/usnistgov/ACVP-Server?tab=readme-ov-file#license
