// Examples calling crsyspqc methods
package main

import (
	"encoding/hex"
	"fmt"
	"slices"

	"github.com/davidi67/crsyspqc"
)

// Display a long string split between head and tail
func headtail(s string, headlen int) string {
	sep := "\n..."
	if len(s) < 2*headlen {
		return s
	}
	outstr := s[:headlen] + sep + s[len(s)-headlen:]
	return outstr
}

func main() {
	var general crsyspqc.General
	ver := general.Version()
	fmt.Println("General.Version:", ver)
	fmt.Printf("General.DllInfo: \"%s\"\n", general.DllInfo())

	///////////
	// DSA
	///////////
	fmt.Println("\nTesting DSA...")
	var dsa crsyspqc.Dsa
	var alg = crsyspqc.ML_DSA_65
	fmt.Println("Alg:", dsa.AlgName(alg))
	fmt.Println(" pklen=", dsa.PublicKeySize(crsyspqc.ML_DSA_65))
	fmt.Println("KeyGen using fresh randomness...")
	pk, sk, err := dsa.KeyGen(alg)
	if err != nil {
		panic("Dsa.KeyGen failed: err")
	}
	fmt.Println("pk:", headtail(hex.EncodeToString(pk), 64))
	fmt.Println("sk:", headtail(hex.EncodeToString(sk), 64))
	// Using known seed
	var seed = "079EAB79AB14747CA01582B59F2624191B0C59FA219CDEB79F66669DAF0E695E"
	alg = crsyspqc.ML_DSA_44
	fmt.Println("Alg:", dsa.AlgName(alg))
	fmt.Println("KeyGen using seed =", seed)
	pk, sk, _ = dsa.KeyGenWithParams(alg, seed)
	fmt.Println("pk:", headtail(hex.EncodeToString(pk), 64))
	fmt.Println("sk:", headtail(hex.EncodeToString(sk), 64))

	fmt.Println("Use sk to sign a message, default options...")
	msg := []byte{0x61, 0x62, 0x63} // "abc"
	sig, _ := dsa.Sign(alg, msg, sk)
	fmt.Println("sig:", headtail(hex.EncodeToString(sig), 96))

	// Verify the signature we just made
	ok, err := dsa.Verify(alg, sig, msg, pk)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Dsa.Verify returns", ok)

	fmt.Println("Create a signature using a known random seed...")
	var testmap = T_mldsa_2 // In datatests.go
	// Get test values from testmap
	alg, err = dsa.LookupAlgByName(testmap["alg"])
	if err != nil {
		panic(err)
	}
	fmt.Println("Alg:", dsa.AlgName(alg))
	msg, _ = hex.DecodeString(testmap["message"])
	sk, _ = hex.DecodeString(testmap["sk"])
	ctx, _ := hex.DecodeString(testmap["context"])
	rndhex := testmap["rnd"] // NB rnd value is passed in hex form
	sig, _ = dsa.SignEx(alg, msg, sk, crsyspqc.SIGOPTS_DEFAULT, ctx, rndhex)
	fmt.Println("rnd =", rndhex)
	fmt.Println("sig:", headtail(hex.EncodeToString(sig), 96))
	// Check this matches the known result
	if b, _ := hex.DecodeString(testmap["signature"]); !slices.Equal(b, sig) {
		fmt.Println("SIGNATURE IS WRONG")
		panic("sig is wrong")
	}

	// Get the public key from the private key
	pk, _ = dsa.PublicKeyFromPrivate(alg, sk)
	// Then verify the signature
	ok, err = dsa.VerifyEx(alg, sig, msg, pk, crsyspqc.SIGOPTS_DEFAULT, ctx)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Dsa.Verify returns", ok)

	testmap = T_slhdsa_1 // In datatests.go
	// Get test values from testmap
	alg, err = dsa.LookupAlgByName(testmap["alg"])
	if err != nil {
		panic(err)
	}
	fmt.Println("Alg:", dsa.AlgName(alg))
	msg, _ = hex.DecodeString(testmap["message"])
	sk, _ = hex.DecodeString(testmap["sk"])
	ctx, _ = hex.DecodeString(testmap["context"])
	opts := crsyspqc.SIGOPTS_DEFAULT
	rndhex, rndexists := testmap["rnd"] // NB rnd value is passed in hex form
	if !rndexists {
		rndhex = ""
		opts = crsyspqc.DETERMINISTIC
		fmt.Println(("No rnd found, so use Deterministic mode"))
	} else {
		fmt.Println("rnd =", rndhex)
	}
	sig, _ = dsa.SignEx(alg, msg, sk, opts, ctx, rndhex)
	fmt.Println("sig:", headtail(hex.EncodeToString(sig), 96))
	// Check this matches the known result
	if b, _ := hex.DecodeString(testmap["signature"]); !slices.Equal(b, sig) {
		fmt.Println("SIGNATURE IS WRONG")
		panic("sig is wrong")
	}

	// Get the public key from the private key
	pk, _ = dsa.PublicKeyFromPrivate(alg, sk)
	// Then verify the signature
	ok, err = dsa.VerifyEx(alg, sig, msg, pk, crsyspqc.SIGOPTS_DEFAULT, ctx)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Dsa.Verify returns", ok)

	fmt.Println("\nTesting ML-DSA-ExternalMu...")
	// Use ExternalMu-ML-DSA.Sign and .Verify
	// Pass the value of "mu" computed externally
	testmap = T_mldsa_externalmu_1 // In datatests.go
	// Get test values from testmap
	alg, err = dsa.LookupAlgByName(testmap["alg"])
	if err != nil {
		panic(err)
	}
	fmt.Println("Alg:", dsa.AlgName(alg))
	mu, _ := hex.DecodeString(testmap["mu"])
	sk, _ = hex.DecodeString(testmap["sk"])
	fmt.Println("mu:", hex.EncodeToString(mu))
	// Must specify ExternalMu AND deterministic options
	opts = crsyspqc.EXTERNALMU | crsyspqc.DETERMINISTIC
	sig, _ = dsa.SignEx(alg, mu, sk, opts, nil, "")
	fmt.Println("sig:", headtail(hex.EncodeToString(sig), 96))
	// Check this matches the known result
	if b, _ := hex.DecodeString(testmap["signature"]); !slices.Equal(b, sig) {
		fmt.Println("SIGNATURE IS WRONG")
		panic("sig is wrong")
	}

	// Get the public key from the private key
	pk, _ = dsa.PublicKeyFromPrivate(alg, sk)
	// Then verify the signature using ExternalMu-ML-DSA.Verify
	ok, err = dsa.VerifyEx(alg, sig, mu, pk, opts, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Dsa.Verify returns", ok)

	///////////
	// KEM
	///////////
	fmt.Println("\nTesting KEM...")
	var kem crsyspqc.Kem
	algk := crsyspqc.ML_KEM_768
	fmt.Println("Alg:", kem.AlgName(algk))

	// Generate a KEM encaps/decaps key pair with fresh randomness
	ek, dk, err := kem.KeyGen(algk)
	if err != nil {
		panic("Kem.KeyGen failed: err")
	}
	fmt.Println("ek:", headtail(hex.EncodeToString(ek), 64))
	fmt.Println("dk:", headtail(hex.EncodeToString(dk), 64))

	// Encapsulate using ek - Use fresh randomness each time
	ct, ss, _ := kem.Encaps(algk, ek)
	fmt.Println("ct:", headtail(hex.EncodeToString(ct), 64))
	fmt.Println("ss: ", headtail(hex.EncodeToString(ss), 64))

	// Decapsulate
	ssd, _ := kem.Decaps(algk, ct, dk)
	fmt.Println("ss':", headtail(hex.EncodeToString(ssd), 64))
	if !slices.Equal(ss, ssd) {
		fmt.Println("ERROR: ss does not match")
		panic("ss does not match")
	}

	// KEM KeyGen known answer test
	testmap = T_mlkem_1 // In datatests.go
	// Get test values from testmap
	algk, err = kem.LookupAlgByName(testmap["alg"])
	if err != nil {
		panic(err)
	}
	fmt.Println("Alg:", kem.AlgName(algk))
	// seed is d||z exactly 64 bytes and is passed in hex form
	rndhex = testmap["seed"] // NB rnd value is passed in hex form
	ek, dk, _ = kem.KeyGenWithParams(algk, rndhex)
	fmt.Println("ek:", headtail(hex.EncodeToString(ek), 64))
	fmt.Println("dk:", headtail(hex.EncodeToString(dk), 64))
	// Check this matches the known result
	if b, _ := hex.DecodeString(testmap["ek"]); !slices.Equal(b, ek) {
		fmt.Println("EK IS WRONG")
		panic("ek is wrong")
	}
	if b, _ := hex.DecodeString(testmap["dk"]); !slices.Equal(b, dk) {
		fmt.Println("DK IS WRONG")
		panic("dk is wrong")
	}

	// ML-KEM-encapDecap-FIPS203-1_1_0_39.json
	testmap = T_mlkem_1024_1 // In datatests.go
	// Get test values from testmap
	algk, err = kem.LookupAlgByName(testmap["alg"])
	if err != nil {
		panic(err)
	}
	fmt.Println("Alg:", kem.AlgName(algk))
	ek, _ = hex.DecodeString(testmap["ek"])
	// The known random value m must be of exactly 32 bytes and is passed in hex form
	rndhex = testmap["m"] // pass in hex-encoded form
	ct, ss, _ = kem.EncapsWithParams(algk, ek, rndhex)
	fmt.Println("ct:", headtail(hex.EncodeToString(ct), 64))
	fmt.Println("ss: ", headtail(hex.EncodeToString(ss), 64))
	// Check this matches the known result
	if b, _ := hex.DecodeString(testmap["ct"]); !slices.Equal(b, ct) {
		fmt.Println("CT IS WRONG")
		panic("ct is wrong")
	}
	if b, _ := hex.DecodeString(testmap["ss"]); !slices.Equal(b, ss) {
		fmt.Println("SS IS WRONG")
		panic("ss is wrong")
	}

	fmt.Println("\nALL DONE.")
}
