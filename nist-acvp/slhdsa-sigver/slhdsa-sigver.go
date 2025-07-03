// @file slhdsa-sigver.go
// @date 2025-07-03T11:53Z
// @author David Ireland <www.cryptosys.net/contact>
// @copyright 2025 DI Management Services Pty Ltd t/a CryptoSys
// @license Apache-2.0

// Test vectors SLH-DSA-sigVer-FIPS205
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/davidi67/crsyspqc"
)

// Run crsyspqc against NIST test vectors
// https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/SLH-DSA-sigVer-FIPS205
// SLH-DSA-sigVer-FIPS205/internalProjection.json
var fname = "SLH-DSA-sigVer-FIPS205-1_1_0_38.json" // download of internalProjection.json

var preHashFile = "SLH-DSA-sigVer-preHashes-1_1_0_38.json"

// Map "parameterSet" in JSON to crsyspqc algorithm
var algsMap = map[string]crsyspqc.DsaAlg{
	"SLH-DSA-SHA2-128s":  crsyspqc.DsaAlg(crsyspqc.SLH_DSA_SHA2_128S),
	"SLH-DSA-SHA2-128f":  crsyspqc.DsaAlg(crsyspqc.SLH_DSA_SHA2_128F),
	"SLH-DSA-SHA2-192s":  crsyspqc.DsaAlg(crsyspqc.SLH_DSA_SHA2_192S),
	"SLH-DSA-SHA2-192f":  crsyspqc.DsaAlg(crsyspqc.SLH_DSA_SHA2_192F),
	"SLH-DSA-SHA2-256s":  crsyspqc.DsaAlg(crsyspqc.SLH_DSA_SHA2_256S),
	"SLH-DSA-SHA2-256f":  crsyspqc.DsaAlg(crsyspqc.SLH_DSA_SHA2_256F),
	"SLH-DSA-SHAKE-128s": crsyspqc.DsaAlg(crsyspqc.SLH_DSA_SHAKE_128S),
	"SLH-DSA-SHAKE-128f": crsyspqc.DsaAlg(crsyspqc.SLH_DSA_SHAKE_128F),
	"SLH-DSA-SHAKE-192s": crsyspqc.DsaAlg(crsyspqc.SLH_DSA_SHAKE_192S),
	"SLH-DSA-SHAKE-192f": crsyspqc.DsaAlg(crsyspqc.SLH_DSA_SHAKE_192F),
	"SLH-DSA-SHAKE-256s": crsyspqc.DsaAlg(crsyspqc.SLH_DSA_SHAKE_256S),
	"SLH-DSA-SHAKE-256f": crsyspqc.DsaAlg(crsyspqc.SLH_DSA_SHAKE_256F),
}

func main() {
	wd, _ := os.Getwd()
	fmt.Println("Working Directory:", wd)
	// Read in JSON file
	// It is in one of: (1) the CWD (2) ./data/ (3) ../data/
	pathname := fname // (1)
	phpath := preHashFile
	content, err := os.ReadFile(pathname)
	if errors.Is(err, os.ErrNotExist) {
		pathname = "./data/" + fname // (2)
		phpath = "./data/" + preHashFile
		content, err = os.ReadFile(pathname)
	}
	if errors.Is(err, os.ErrNotExist) {
		pathname = "../data/" + fname // (3)
		phpath = "../data/" + preHashFile
		content, err = os.ReadFile(pathname)
	}
	if err != nil {
		// We didn't find it
		panic(err)
	}
	fmt.Println("FILEPATH:", pathname)
	fmt.Println(filepath.Abs(pathname))
	// Read in pre-hash JSON file
	phcontent, err := os.ReadFile(phpath)
	if err != nil {
		panic(err)
	}

	// Get JSON data in a map
	var data map[string]any
	err = json.Unmarshal(content, &data)
	if err != nil {
		panic(err)
	}
	// And preHash data
	var phdata map[string]any
	err = json.Unmarshal(phcontent, &phdata)
	if err != nil {
		panic(err)
	}
	// preHashes contains a map of pre-computed hash values over the message keyed on the tcId value
	preHashes := phdata["preHashes"].(map[string]any)
	/*
			    "preHashes": {
		        "106": {
		            "tcId": 106,
		            "messagelength": 5297,
		            "hashAlg": "SHA2-512",
		            "ph": "4a54afb49a57991ff2a799b06b718676c1b489bc1c1e337c018355fa0043e2160e0a19692b93a007d60a3c5761c8d52075642923cc52d8502eefd228cbc0cebc"
		        },
		        "107": {
		            "tcId": 107,
				//...etc
	*/

	// Global Dsa variable
	var dsa crsyspqc.Dsa

	fmt.Println("vsId:", data["vsId"])
	ntestsdone := 0
	// for each testGroup tg in data
	for _, tg := range data["testGroups"].([]any) {
		fmt.Println("**tgId:", tg.(map[string]any)["tgId"])
		// Get algorithm from parameterSet string
		algStr := tg.(map[string]any)["parameterSet"].(string)
		alg := algsMap[algStr]
		fmt.Println("alg:", crsyspqc.Dsa.AlgName(dsa, alg))

		// Figure out Dsa.Sign options, modes and variants
		isprehash := tg.(map[string]any)["preHash"].(string) == "preHash"
		isinternal := tg.(map[string]any)["signatureInterface"].(string) == "internal"

		// for each test case tc in tg['tests']
		for _, tc := range tg.(map[string]any)["tests"].([]any) {
			fmt.Println("  tcId:", tc.(map[string]any)["tcId"])

			// Decode public key
			pk, _ := hex.DecodeString(tc.(map[string]any)["pk"].(string))
			// and signature
			sig, _ := hex.DecodeString(tc.(map[string]any)["signature"].(string))

			var msg []byte
			var ctx []byte
			var isok bool
			testPassed := tc.(map[string]any)["testPassed"].(bool)
			reason := tc.(map[string]any)["reason"].(string)
			fmt.Println("   reason:", reason)

			// Get message and context, if any
			msg, _ = hex.DecodeString(tc.(map[string]any)["message"].(string))
			context, exists := tc.(map[string]any)["context"]
			if exists {
				ctx, _ = hex.DecodeString(context.(string))
			}

			// Deal with internal option
			opts := crsyspqc.SIGOPTS_DEFAULT
			if isinternal {
				opts |= crsyspqc.INTERNAL
			}

			// Verify signature
			isok = false
			if isprehash {
				// If preHash, get required ph value and algorithm
				tcid := fmt.Sprintf("%v", tc.(map[string]any)["tcId"].(float64))
				phalgstr := preHashes[tcid].(map[string]any)["hashAlg"]
				phvalstr := preHashes[tcid].(map[string]any)["ph"]
				//fmt.Println("preHash:", phalgstr, phvalstr)
				phalg, _ := lookupHashAlg(phalgstr.(string))
				phval, _ := hex.DecodeString(phvalstr.(string))

				isok, err = dsa.VerifyPreHash(alg, sig, phval, phalg, pk, opts, ctx)
				if err != nil {
					isok = false
				}
			} else {
				isok, err = dsa.VerifyEx(alg, sig, msg, pk, opts, ctx)
				if err != nil {
					isok = false
				}
			}
			fmt.Printf("   Dsa.Verify returns %v, expected %v\n", isok, testPassed)
			if isok != testPassed {
				panic("Unexpected testPassed result")
			}

			ntestsdone++
		}
	}
	fmt.Println("ntestsdone=", ntestsdone)
}

// Lookup PreHashAlg by string used in NIST ACVP tests
func lookupHashAlg(s string) (alg crsyspqc.PreHashAlg, err error) {
	var prehashAlgByString = map[string]crsyspqc.PreHashAlg{
		"SHA2-224":     crsyspqc.SHA224,
		"SHA2-256":     crsyspqc.SHA256,
		"SHA2-384":     crsyspqc.SHA384,
		"SHA2-512":     crsyspqc.SHA512,
		"SHA2-512/224": crsyspqc.SHA512_224,
		"SHA2-512/256": crsyspqc.SHA512_256,
		"SHA3-224":     crsyspqc.SHA3_224,
		"SHA3-256":     crsyspqc.SHA3_256,
		"SHA3-384":     crsyspqc.SHA3_384,
		"SHA3-512":     crsyspqc.SHA3_512,
		"SHAKE-128":    crsyspqc.SHAKE128_256,
		"SHAKE-256":    crsyspqc.SHAKE256_512,
	}
	alg, found := prehashAlgByString[s]
	if !found {
		return alg, fmt.Errorf("%s does not match a supported hash algorithm", s)
	}
	return alg, nil
}
