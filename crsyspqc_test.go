package crsyspqc_test

import (
	"encoding/hex"
	"slices"
	"testing"

	"github.com/davidi67/crsyspqc"
)

func TestPkLen(t *testing.T) {
	var dsa crsyspqc.Dsa
	want := 1952
	pklen := dsa.PublicKeySize(crsyspqc.ML_DSA_65)
	if pklen != want {
		t.Errorf("pklen=%d, want %d", pklen, want)
	}
}

func TestPkLenTableDriven(t *testing.T) {
	var tests = []struct {
		alg  crsyspqc.DsaAlg
		want int
	}{
		{crsyspqc.ML_DSA_44, 1312},
		{crsyspqc.ML_DSA_65, 1952},
		{crsyspqc.ML_DSA_87, 2592},
		{crsyspqc.SLH_DSA_SHA2_128F, 32},
		{crsyspqc.SLH_DSA_SHAKE_192F, 48},
		{crsyspqc.SLH_DSA_SHAKE_256S, 64},
	}

	for _, tt := range tests {
		var dsa crsyspqc.Dsa
		testname := dsa.AlgName(tt.alg)
		t.Run(testname, func(t *testing.T) {
			ans := dsa.PublicKeySize(tt.alg)
			if ans != tt.want {
				t.Errorf("got %d, want %d", ans, tt.want)
			}
		})
	}
}

func TestMLDSAKeyGenSignVerify(t *testing.T) {
	// 1. Generate an ML-DSA key pair from a known seed
	// 2. Use to sign the string "abc" in deterministic manner in two ways
	//   a. Using the generated expanded private key
	//   b. Using the seed key
	//   then check the signatures are the same
	// 3. Check that the public key extracted from both forms of private key matches the generated public key
	// 4. Verify the signature using the generated public key
	var dsa crsyspqc.Dsa
	alg := crsyspqc.ML_DSA_44
	var seed = "079EAB79AB14747CA01582B59F2624191B0C59FA219CDEB79F66669DAF0E695E"
	pk, sk, err := dsa.KeyGenWithParams(alg, seed)
	if err != nil {
		t.Error("Dsa.KeyGen returns error", err)
	}
	msg := []byte{0x61, 0x62, 0x63} // "abc"
	// a. Sign using extended private key
	sig, _ := dsa.SignEx(alg, msg, sk, crsyspqc.DETERMINISTIC, nil, "")
	// b. Sign using private key in seed form (hex decoded to bytes)
	skseed, _ := hex.DecodeString(seed)
	sig1, _ := dsa.SignEx(alg, msg, skseed, crsyspqc.DETERMINISTIC, nil, "")
	if !slices.Equal(sig1, sig) {
		t.Error("Signatures do not match")
	}
	// Derive public key from both forms of private key
	// and compare to generated pk
	pkfromseed, _ := dsa.PublicKeyFromPrivate(alg, skseed)
	if !slices.Equal(pk, pkfromseed) {
		t.Error("Public key derived from seed is wrong")
	}
	pkfromsk, _ := dsa.PublicKeyFromPrivate(alg, sk)
	if !slices.Equal(pk, pkfromsk) {
		t.Error("Public key derived from sk is wrong")
	}
	// Now verify the signature
	ok, err := dsa.Verify(alg, sig, msg, pk)
	if !ok || err != nil {
		t.Error("Signature did not verify")
	}
}

func TestMLKEMKeyGenEncapsDecaps(t *testing.T) {
	var kem crsyspqc.Kem
	// Generate KEM key pair (ek,dk) using known random input
	algk := crsyspqc.ML_KEM_512
	var seed = "CDF4E658BDD4636F09F70BD76CE6D1AF028562586EF237C7481033EE03C31FF238CD80FE6CD34678DE86E55E145BAF191B675C19C485C54EF3522C044D42F6EE"
	ek, dk, err := kem.KeyGenWithParams(algk, seed)
	if err != nil {
		t.Error("Kem.KeyGen returns error", err)
	}
	// Use Kem.Encaps with known random value "m" to generate (ct,ss)
	m := "8FA6B817B59059DED3AA03A34120C35D0976A61AE9AAB8FB4C8F2EA7ECF9BFD4"
	ct, ss, _ := kem.EncapsWithParams(algk, ek, m)

	// Check we get same ss with Decaps
	ss1, _ := kem.Decaps(algk, ct, dk)
	if !slices.Equal(ss1, ss) {
		t.Error("Shared key ss does not match")
	}
}
