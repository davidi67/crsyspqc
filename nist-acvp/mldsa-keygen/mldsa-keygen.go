// @file mldsa-keygen.go
// @date 2025-07-06T06:07Z
// @author David Ireland <www.cryptosys.net/contact>
// @copyright 2025 DI Management Services Pty Ltd t/a CryptoSys
// @license Apache-2.0

// Test vectors ML-DSA-keyGen-FIPS204
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/davidi67/crsyspqc"
)

// Run crsyspqc against NIST test vectors
// https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-DSA-keyGen-FIPS204
// ML-DSA-keyGen-FIPS204/internalProjection.json
var fname = "ML-DSA-keyGen-FIPS204-1_1_0_39.json" // download of internalProjection.json

// Map "parameterSet" in JSON to crsyspqc algorithm
var algsMap = map[string]crsyspqc.DsaAlg{
	"ML-DSA-44": crsyspqc.DsaAlg(crsyspqc.ML_DSA_44),
	"ML-DSA-65": crsyspqc.DsaAlg(crsyspqc.ML_DSA_65),
	"ML-DSA-87": crsyspqc.DsaAlg(crsyspqc.ML_DSA_87),
}

func main() {
	wd, _ := os.Getwd()
	fmt.Println("Working Directory:", wd)
	// Read in JSON file
	// It is in one of: (1) the CWD (2) ./data/ (3) ../data/
	pathname := fname // (1)
	content, err := os.ReadFile(pathname)
	if errors.Is(err, os.ErrNotExist) {
		pathname = "./data/" + fname // (2)
		content, err = os.ReadFile(pathname)
	}
	if errors.Is(err, os.ErrNotExist) {
		pathname = "../data/" + fname // (3)
		content, err = os.ReadFile(pathname)
	}
	if err != nil {
		// We didn't find it
		panic(err)
	}
	fmt.Println("FILEPATH:", pathname)
	fmt.Println(filepath.Abs(pathname))

	// Get JSON data in a map
	var data map[string]any
	err = json.Unmarshal(content, &data)
	if err != nil {
		panic(err)
	}

	// Create a Dsa instance
	var dsa crsyspqc.Dsa

	fmt.Println("vsId:", data["vsId"])
	fmt.Println("algorithm:", data["algorithm"])
	fmt.Println("mode:", data["mode"])
	ntestsdone := 0
	// for each testGroup tg in data
	for _, tg := range data["testGroups"].([]any) {
		fmt.Println("**tgId:", tg.(map[string]any)["tgId"])
		// Get algorithm from parameterSet string
		algStr := tg.(map[string]any)["parameterSet"].(string)
		alg := algsMap[algStr]
		fmt.Println("alg:", crsyspqc.Dsa.AlgName(dsa, alg))
		// for each test case tc in tg['tests']
		for _, tc := range tg.(map[string]any)["tests"].([]any) {
			//fmt.Println("  tcId:", tc.(map[string]any)["tcId"])
			// Get seed in hex form
			seed := tc.(map[string]any)["seed"].(string)

			// Generate keys using known test vector
			pk, sk, err := dsa.KeyGenWithParams(alg, seed)
			if err != nil {
				panic(err)
			}
			// Check against known test vectors for (pk, sk)
			if pkok, _ := hex.DecodeString(tc.(map[string]any)["pk"].(string)); !slices.Equal(pk, pkok) {
				fmt.Println("PK DOES NOT MATCH")
				panic("pk is wrong")
			}
			if skok, _ := hex.DecodeString(tc.(map[string]any)["sk"].(string)); !slices.Equal(sk, skok) {
				fmt.Println("SK DOES NOT MATCH")
				panic("sk is wrong")
			}

			ntestsdone++
		}
	}
	fmt.Println("ntestsdone=", ntestsdone)
}
