// @file slhdsa-siggen.go
// @date 2025-07-06T06:07Z
// @author David Ireland <www.cryptosys.net/contact>
// @copyright 2025 DI Management Services Pty Ltd t/a CryptoSys
// @license Apache-2.0

// Test vectors SLH-DSA-sigGen-FIPS205
package main

import (
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "slices"
    "time"

    "github.com/davidi67/crsyspqc"
)

// Run crsyspqc against NIST test vectors
// https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/SLH-DSA-sigGen-FIPS205
// SLH-DSA-sigGen-FIPS205/internalProjection.json
var fname = "SLH-DSA-sigGen-FIPS205-1_1_0_38.json" // download of internalProjection.json

var preHashFile = "SLH-DSA-sigGen-preHashes-1_1_0_38.json"

// CAUTION: this takes several minutes to execute.

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

    // Create a Dsa instance
    var dsa crsyspqc.Dsa

    start := time.Now()
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
        isdeterministic := tg.(map[string]any)["deterministic"].(bool)
        //fmt.Println("deterministic:", isdeterministic)
        //fmt.Println("preHash:", tg.(map[string]any)["preHash"])
        isprehash := tg.(map[string]any)["preHash"].(string) == "preHash"
        //fmt.Println("isprehash:", isprehash)
        isinternal := tg.(map[string]any)["signatureInterface"].(string) == "internal"

        // for each test case tc in tg['tests']
        for _, tc := range tg.(map[string]any)["tests"].([]any) {
            //fmt.Println("  tcId:", tc.(map[string]any)["tcId"])

            // Decode private key
            sk, _ := hex.DecodeString(tc.(map[string]any)["sk"].(string))
            opts := crsyspqc.SIGOPTS_DEFAULT

            var msg []byte
            var ctx []byte
            var sig []byte

            // Get message and context, if any
            msg, _ = hex.DecodeString(tc.(map[string]any)["message"].(string))
            context, exists := tc.(map[string]any)["context"]
            if exists {
                ctx, _ = hex.DecodeString(context.(string))
            }

            // Deal with rnd value (NB passed in hex form)
            rndhex := ""
            if isdeterministic {
                opts |= crsyspqc.DETERMINISTIC
                rndhex = ""
            } else {
                rndhex = tc.(map[string]any)["additionalRandomness"].(string)
            }

            // Catch internal
            if isinternal {
                opts |= crsyspqc.INTERNAL
            }

            // Compute signature
            if isprehash {
                // If preHash, get required ph value and algorithm
                tcid := fmt.Sprintf("%v", tc.(map[string]any)["tcId"].(float64))
                phalgstr := preHashes[tcid].(map[string]any)["hashAlg"]
                phvalstr := preHashes[tcid].(map[string]any)["ph"]
                //fmt.Println("preHash:", phalgstr, phvalstr)
                phalg, _ := lookupHashAlg(phalgstr.(string))
                phval, _ := hex.DecodeString(phvalstr.(string))
                sig, err = dsa.SignPreHash(alg, phval, phalg, sk, opts, ctx, rndhex)
                if err != nil {
                    panic(err)
                }
            } else {
                sig, err = dsa.SignEx(alg, msg, sk, opts, ctx, rndhex)
                if err != nil {
                    panic(err)
                }
            }

            // Check against known test vector
            if sigok, _ := hex.DecodeString(tc.(map[string]any)["signature"].(string)); !slices.Equal(sig, sigok) {
                fmt.Println("SIGNATURE DOES NOT MATCH")
                panic("signature is wrong")
            }

            ntestsdone++
        }
    }
    fmt.Println("ntestsdone=", ntestsdone)
    elapsed := time.Since(start)
    fmt.Println("Elapsed time:", elapsed)
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
