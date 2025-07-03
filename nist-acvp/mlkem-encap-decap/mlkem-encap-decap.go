// @file mlkem-encap-decap.go
// @date 2025-07-03T11:53Z
// @author David Ireland <www.cryptosys.net/contact>
// @copyright 2025 DI Management Services Pty Ltd t/a CryptoSys
// @license Apache-2.0

// Test vectors ML-KEM-encapDecap-FIPS203
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
// https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-encapDecap-FIPS203
// ML-KEM-encapDecap-FIPS203/internalProjection.json
var fname = "ML-KEM-encapDecap-FIPS203-1_1_0_39.json"

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
	// It is located in one of: (1) the CWD (2) ./data/ (3) ../data/
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

	// Global Kem variable
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
		function := tg.(map[string]any)["function"].(string)
		fmt.Println("function:", function)
		// for each test case tc in tg['tests']
		for _, tc := range tg.(map[string]any)["tests"].([]any) {
			//fmt.Println("  tcId:", tc.(map[string]any)["tcId"])
			//fmt.Println("  Reason:", tc.(map[string]any)["reason"])
			switch function {
			case "encapsulation":
				// Expecting ek, dk, c, k, m, reason
				ek, _ := hex.DecodeString(tc.(map[string]any)["ek"].(string))
				seed := tc.(map[string]any)["m"].(string)
				ss, ct, err := kem.EncapsWithParams(alg, ek, seed)
				if err != nil {
					panic(err)
				}
				//fmt.Println("ss:", hex.EncodeToString(ss))
				// Check against known test vectors for (ss, ct) aka (k, c)
				if ssok, _ := hex.DecodeString(tc.(map[string]any)["k"].(string)); !slices.Equal(ss, ssok) {
					fmt.Println("SS DOES NOT MATCH")
					panic("ss is wrong")
				}
				if ctok, _ := hex.DecodeString(tc.(map[string]any)["c"].(string)); !slices.Equal(ct, ctok) {
					fmt.Println("CT DOES NOT MATCH")
					panic("ct is wrong")
				}
				// Now decapsulate using dk
				dk, _ := hex.DecodeString(tc.(map[string]any)["dk"].(string))
				ss1, _ := kem.Decaps(alg, ct, dk)
				if ssok, _ := hex.DecodeString(tc.(map[string]any)["k"].(string)); !slices.Equal(ss1, ssok) {
					fmt.Println("SS' DOES NOT MATCH")
					panic("ss' is wrong")
				}
			case "decapsulation":
				// Expecting ek, dk:  global; tests: c, k, reason
				dk, _ := hex.DecodeString(tg.(map[string]any)["dk"].(string))
				ct, _ := hex.DecodeString(tc.(map[string]any)["c"].(string))
				ss, err := kem.Decaps(alg, ct, dk)
				if err != nil {
					panic(err)
				}
				if ssok, _ := hex.DecodeString(tc.(map[string]any)["k"].(string)); !slices.Equal(ss, ssok) {
					fmt.Println("SS DOES NOT MATCH")
					panic("ss is wrong")
				}
			}

			ntestsdone++
		}
	}
	fmt.Printf("ALL DONE. %d tests completed", ntestsdone)
}
