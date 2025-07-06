// @file mlkem-keygen.go
// @date 2025-07-06T06:07Z
// @author David Ireland <www.cryptosys.net/contact>
// @copyright 2025 DI Management Services Pty Ltd t/a CryptoSys
// @license Apache-2.0

// Test vectors ML-KEM-keyGen-FIPS203
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
// https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-keyGen-FIPS203
// ML-KEM-keyGen-FIPS203/internalProjection.json
var fname = "ML-KEM-keyGen-FIPS203-1_1_0_39.json" // download of internalProjection.json

// Map "parameterSet" in JSON to crsyspqc algorithm
var algsMap = map[string]crsyspqc.KemAlg{
	"ML-KEM-512":  crsyspqc.ML_KEM_512,
	"ML-KEM-768":  crsyspqc.ML_KEM_768,
	"ML-KEM-1024": crsyspqc.ML_KEM_1024,
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

	// Create a Kem instance
	var kem crsyspqc.Kem

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
		fmt.Println("alg:", crsyspqc.Kem.AlgName(kem, alg))
		// for each test case tc in tg['tests']
		for _, tc := range tg.(map[string]any)["tests"].([]any) {
			//fmt.Println("  tcId:", tc.(map[string]any)["tcId"])
			// Compose (d||z) in hex form
			genrandhex := tc.(map[string]any)["d"].(string) + tc.(map[string]any)["z"].(string)
			//fmt.Println("  genrandhex:", genrandhex)

			// Generate keys using known test vector
			ek, dk, err := kem.KeyGenWithParams(alg, genrandhex)
			if err != nil {
				panic(err)
			}
			// Check against known test vectors for (ek, dk)
			if ekok, _ := hex.DecodeString(tc.(map[string]any)["ek"].(string)); !slices.Equal(ek, ekok) {
				fmt.Println("EK DOES NOT MATCH")
				panic("ek is wrong")
			}
			if dkok, _ := hex.DecodeString(tc.(map[string]any)["dk"].(string)); !slices.Equal(dk, dkok) {
				fmt.Println("DK DOES NOT MATCH")
				panic("dk is wrong")
			}

			ntestsdone++
		}
	}
	fmt.Println("ntestsdone=", ntestsdone)
}
