// Copyright (C) 2025 David Ireland, DI Management Services Pty Limited
// t/a CryptoSys <www.cryptosys.net>. All rights reserved. 

// Package crsyspqc provides an interface to CryptoSys PQC for go programmers.
//
// CryptoSys PQC provides Post-Quantum Cryptography algorithms as specified by NIST.
// Requires CryptoSys PQC to be installed on your computer, available for free at
// https://www.cryptosys.net/pqc/
//
// References:
//   - [FIPS203] Module-Lattice-based Key-Encapsulation Mechanism Standard
//   - [FIPS204] Module-Lattice-Based Digital Signature Standard
//   - [FIPS205] Stateless Hash-Based Digital Signature Standard
//
// [FIPS203]: https://doi.org/10.6028/NIST.FIPS.203
// [FIPS204]: https://doi.org/10.6028/NIST.FIPS.204
// [FIPS205]: https://doi.org/10.6028/NIST.FIPS.205
//
// @license Apache-2.0 http://www.apache.org/licenses/
package crsyspqc

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

const dllName string = "diCrPQC.dll"

// INTERNAL UTILS
func stringToCharPtr(str string) *uint8 {
	// https://medium.com/@justen.walker/breaking-all-the-rules-using-go-to-call-windows-api-2cbfd8c79724
	chars := append([]byte(str), 0) // null terminated
	return &chars[0]
}

// ///////////////
// GENERAL
// ///////////////

// General has methods that provide diagnostic info about the core native DLL.
type General struct{}

// Version returns the version number of core native diCrPQC DLL
// An integer of the form Major * 10000 + Minor * 100 + Release
//
//	var general crsyspqc.General
//	fmt.Println(general.Version())  // 10000
func (g General) Version() int {
	// long	PQC_Version (void)
	var proc = syscall.NewLazyDLL(dllName).NewProc("PQC_Version")
	ret, _, _ := proc.Call(0) // NB must have at least one parameter even if function takes void
	return int(ret)
}

// DllInfo returns information about the core native DLL.
//
// For example
//
//	"Platform=X64;Compiled=Apr 2 2025 19:13:31;Licence=T"
func (g General) DllInfo() string {
	// long	PQC_DllInfo (char *szOutput, long nOutChars, long nOptions)
	var proc = syscall.NewLazyDLL(dllName).NewProc("PQC_DllInfo")
	nchars, _, _ := proc.Call(0, 0, 0)
	buf := make([]byte, nchars+1) // NB add one for null-terminated string output
	nchars, _, _ = proc.Call(
		uintptr(unsafe.Pointer(&buf[0])), nchars, 0)
	outstr := string(buf[:nchars]) //len(buf)-1
	return outstr
}

// Local function to lookup error string for errCode
func errorLookup(errCode int) string {
	// long __stdcall PQC_ErrorLookup(char *szOutput, long nOutChars, long nErrCode);
	const MAXERRORLEN = 128
	var proc = syscall.NewLazyDLL(dllName).NewProc("PQC_ErrorLookup")
	nchars, _, _ := proc.Call(0, 0, uintptr(errCode))
	if nchars <= 0 {
		return "ERROR: " + fmt.Sprintf("%d", errCode)
	}
	nchars = MAXERRORLEN
	buf := make([]byte, nchars)
	nchars, _, _ = proc.Call(
		uintptr(unsafe.Pointer(&buf[0])), uintptr(nchars), uintptr(errCode))
	outstr := string(buf[:nchars]) //len(buf)-1
	return outstr
}

// ///////////////
// DSA
// ///////////////

// DsaAlg enumerates the provided DSA algorithms
type DsaAlg int

const (
	ML_DSA_44          DsaAlg = 0x20 // ML-DSA-44 from FIPS.204 (based on Dilithium2)
	ML_DSA_65          DsaAlg = 0x21 // ML-DSA-65 from FIPS.204 (based on Dilithium3)
	ML_DSA_87          DsaAlg = 0x22 // ML-DSA-87 from FIPS.204 (based on Dilithium5)
	SLH_DSA_SHA2_128S  DsaAlg = 0x32 // SLH-DSA-SHA2-128s from FIPS.205
	SLH_DSA_SHA2_128F  DsaAlg = 0x33 // SLH-DSA-SHA2-128f from FIPS.205
	SLH_DSA_SHA2_192S  DsaAlg = 0x34 // SLH-DSA-SHA2-192s from FIPS.205
	SLH_DSA_SHA2_192F  DsaAlg = 0x35 // SLH-DSA-SHA2-192f from FIPS.205
	SLH_DSA_SHA2_256S  DsaAlg = 0x36 // SLH-DSA-SHA2-256s from FIPS.205
	SLH_DSA_SHA2_256F  DsaAlg = 0x37 // SLH-DSA-SHA2-256f from FIPS.205
	SLH_DSA_SHAKE_128S DsaAlg = 0x3A // SLH-DSA-SHAKE-128s from FIPS.205
	SLH_DSA_SHAKE_128F DsaAlg = 0x3B // SLH-DSA-SHAKE-128f from FIPS.205
	SLH_DSA_SHAKE_192S DsaAlg = 0x3C // SLH-DSA-SHAKE-192s from FIPS.205
	SLH_DSA_SHAKE_192F DsaAlg = 0x3D // SLH-DSA-SHAKE-192f from FIPS.205
	SLH_DSA_SHAKE_256S DsaAlg = 0x3E // SLH-DSA-SHAKE-256s from FIPS.205
	SLH_DSA_SHAKE_256F DsaAlg = 0x3F // SLH-DSA-SHAKE-256f from FIPS.205
)

// Signature options for DSA
type SigOpts int

const (
	SIGOPTS_DEFAULT SigOpts = 0         // Default signing options (hedged with fresh randomness)
	DETERMINISTIC   SigOpts = 0x2000    // Use deterministic variant when signing
	INTERNAL        SigOpts = 0x4000000 // Use Sign_internal or Verify_internal algorithm (for testing purposes)
	EXTERNALMU      SigOpts = 0x8000000 // Use ExternalMu-ML-DSA.Sign or ExternalMu-ML-DSA.Verify algorithm (ML-DSA only)
)

// Lookup table for alg code by string
var algDsaByString = map[string]DsaAlg{
	"ML-DSA-44":          ML_DSA_44,
	"ML-DSA-65":          ML_DSA_65,
	"ML-DSA-87":          ML_DSA_87,
	"SLH-DSA-SHA2-128s":  SLH_DSA_SHA2_128S,
	"SLH-DSA-SHA2-128f":  SLH_DSA_SHA2_128F,
	"SLH-DSA-SHA2-192s":  SLH_DSA_SHA2_192S,
	"SLH-DSA-SHA2-192f":  SLH_DSA_SHA2_192F,
	"SLH-DSA-SHA2-256s":  SLH_DSA_SHA2_256S,
	"SLH-DSA-SHA2-256f":  SLH_DSA_SHA2_256F,
	"SLH-DSA-SHAKE-128s": SLH_DSA_SHAKE_128S,
	"SLH-DSA-SHAKE-128f": SLH_DSA_SHAKE_128F,
	"SLH-DSA-SHAKE-192s": SLH_DSA_SHAKE_192S,
	"SLH-DSA-SHAKE-192f": SLH_DSA_SHAKE_192F,
	"SLH-DSA-SHAKE-256s": SLH_DSA_SHAKE_256S,
	"SLH-DSA-SHAKE-256f": SLH_DSA_SHAKE_256F,
}

// Dsa provides methods to generate keys, sign and verify with the DSA algorithms.
type Dsa struct{}

// LookupAlgByName gets the algorithm code from its name.
//
// NB is case sensitive, expects dash "-" not underscore. For example
//
//	var dsa crsyspqc.Dsa
//	alg, err = dsa.LookupAlgByName("SLH-DSA-SHAKE-256s")
func (d Dsa) LookupAlgByName(s string) (alg DsaAlg, err error) {
	alg, found := algDsaByString[s]
	if !found {
		return alg, fmt.Errorf("%s does not match a valid DSA algorithm", s)
	}
	return alg, nil
}

// AlgName gets the algorithm name from its code
func (d Dsa) AlgName(alg DsaAlg) string {
	// long	PQC_AlgName (char *szOutput, long nOutChars, long nOptions)
	var proc = syscall.NewLazyDLL(dllName).NewProc("PQC_AlgName")
	flags := int(alg)
	nchars, _, _ := proc.Call(0, 0, uintptr(flags))
	buf := make([]byte, nchars+1)
	nchars, _, _ = proc.Call(
		uintptr(unsafe.Pointer(&buf[0])), nchars, uintptr(flags))
	outstr := string(buf[:nchars])
	return outstr
}

func dsa_publickeysize(alg DsaAlg) int {
	// long __stdcall DSA_PublicKeySize(long nAlg);
	var proc = syscall.NewLazyDLL(dllName).NewProc("DSA_PublicKeySize")
	ret, _, _ := proc.Call(uintptr(alg))
	return int(ret)
}

// PublicKeySize returns length in bytes of public key for the given DSA algorithm.
//
//	var dsa crsyspqc.Dsa
//	fmt.Println(dsa.PublicKeySize(crsyspqc.ML_DSA_65))  // 1952
func (d Dsa) PublicKeySize(alg DsaAlg) int {
	return dsa_publickeysize(alg)
}

func dsa_privatekeysize(alg DsaAlg) int {
	// long __stdcall DSA_PrivateKeySize(long nAlg);
	var proc = syscall.NewLazyDLL(dllName).NewProc("DSA_PrivateKeySize")
	ret, _, _ := proc.Call(uintptr(alg))
	return int(ret)
}

// Return length in bytes of (expanded) private key for the given DSA algorithm.
func (d Dsa) PrivateKeySize(alg DsaAlg) int {
	return dsa_privatekeysize(alg)
}

func dsa_signaturesize(alg DsaAlg) int {
	// long DSA_SignatureSize (long nAlg)
	var proc = syscall.NewLazyDLL(dllName).NewProc("DSA_SignatureSize")
	ret, _, _ := proc.Call(uintptr(alg))
	return int(ret)
}

// Return length in bytes of signature for the given DSA algorithm
func (d Dsa) SignatureSize(alg DsaAlg) int {
	return dsa_signaturesize(alg)
}

// Generate a DSA signing key pair (pk, sk)
func (d Dsa) KeyGen(alg DsaAlg) (pk []byte, sk []byte, err error) {
	// long __stdcall DSA_KeyGen(unsigned char *lpOutput, long nOutBytes, const char *szParams, long nOptions);
	var proc = syscall.NewLazyDLL(dllName).NewProc("DSA_KeyGen")
	flags := int(alg)
	nbytes, _, _ := proc.Call(
		0, 0,
		uintptr(unsafe.Pointer(stringToCharPtr(""))),
		uintptr(flags))
	if int(nbytes) < 0 {
		return pk, sk, errors.New(errorLookup(int(nbytes)))
	}
	buf := make([]byte, nbytes)
	_, _, _ = proc.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		nbytes,
		uintptr(unsafe.Pointer(stringToCharPtr(""))),
		uintptr(flags))
	// Split pk||sk
	pklen := dsa_publickeysize(alg)
	pk = buf[:pklen]
	sk = buf[pklen:]

	return pk, sk, nil
}

// Generate a DSA signing key pair (pk, sk) passing known randomness encoded in hex
func (d Dsa) KeyGenWithParams(alg DsaAlg, params string) (pk []byte, sk []byte, err error) {
	// long __stdcall DSA_KeyGen(unsigned char *lpOutput, long nOutBytes, const char *szParams, long nOptions);
	var proc = syscall.NewLazyDLL(dllName).NewProc("DSA_KeyGen")
	flags := int(alg)
	nbytes, _, _ := proc.Call(
		0, 0, uintptr(unsafe.Pointer(stringToCharPtr(params))), uintptr(flags))
	if int(nbytes) < 0 {
		return pk, sk, errors.New(errorLookup(int(nbytes)))
	}
	buf := make([]byte, nbytes)
	_, _, _ = proc.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		nbytes,
		uintptr(unsafe.Pointer(stringToCharPtr(params))),
		uintptr(flags))
	// Split pk||sk
	pklen := dsa_publickeysize(alg)
	pk = buf[:pklen]
	sk = buf[pklen:]

	return pk, sk, nil
}

// Generate a DSA signature over a message
// Default options: hedged with fresh randomness, no context
func (d Dsa) Sign(alg DsaAlg, msg []byte, privatekey []byte) (sig []byte, err error) {
	// long __stdcall DSA_Sign(unsigned char *lpOutput, long nOutBytes, const unsigned char *lpMsg, long nMsgLen,
	//	const unsigned char *lpPrivateKey, long nKeyLen, const unsigned char *lpContext, long nCtxLen, const char *szParams, long nOptions);
	var proc = syscall.NewLazyDLL(dllName).NewProc("DSA_Sign")
	//fmt.Println(alg)
	flags := int(alg)
	nbytes, _, _ := proc.Call(0, 0,
		uintptr(unsafe.Pointer(&msg[0])),
		uintptr(len(msg)),
		uintptr(unsafe.Pointer(&privatekey[0])),
		uintptr(len(privatekey)),
		uintptr(unsafe.Pointer(nil)),
		uintptr(0),
		uintptr(unsafe.Pointer(stringToCharPtr(""))),
		uintptr(flags))
	//fmt.Println("siglen=", nbytes)
	if int(nbytes) < 0 {
		return sig, errors.New(errorLookup(int(nbytes)))
	}
	sig = make([]byte, nbytes)
	_, _, _ = proc.Call(
		uintptr(unsafe.Pointer(&sig[0])),
		nbytes,
		uintptr(unsafe.Pointer(&msg[0])),
		uintptr(len(msg)),
		uintptr(unsafe.Pointer(&privatekey[0])),
		uintptr(len(privatekey)),
		uintptr(unsafe.Pointer(nil)),
		uintptr(0),
		uintptr(unsafe.Pointer(stringToCharPtr(""))),
		uintptr(flags))

	return sig, nil
}

// Generate a DSA signature over a message with extended options.
//
//   - [SigOpts]: to set alternative mode for signing (default hedged with fresh randomness).
//   - context: pass a context value (pass nil for no context).
//   - params: pass a known random test value in params (encoded in hex) - hedged mode only (pass "" to ignore).
func (d Dsa) SignEx(alg DsaAlg, msg []byte, privatekey []byte, opts SigOpts, context []byte, params string) (sig []byte, err error) {
	// long __stdcall DSA_Sign(unsigned char *lpOutput, long nOutBytes, const unsigned char *lpMsg, long nMsgLen,
	//	const unsigned char *lpPrivateKey, long nKeyLen, const unsigned char *lpContext, long nCtxLen, const char *szParams, long nOptions);
	var proc = syscall.NewLazyDLL(dllName).NewProc("DSA_Sign")
	flags := int(alg) | int(opts)
	var ctx *byte
	var ctxlen int
	if len(context) == 0 || context == nil {
		ctx = nil
		ctxlen = 0
	} else {
		ctx = &context[0]
		ctxlen = len(context)
	}
	nbytes, _, _ := proc.Call(
		0, 0,
		uintptr(unsafe.Pointer(&msg[0])),
		uintptr(len(msg)),
		uintptr(unsafe.Pointer(&privatekey[0])),
		uintptr(len(privatekey)),
		uintptr(unsafe.Pointer(ctx)),
		uintptr(ctxlen),
		uintptr(unsafe.Pointer(stringToCharPtr(params))),
		uintptr(flags))
	if int(nbytes) < 0 {
		return sig, errors.New(errorLookup(int(nbytes)))
	}
	sig = make([]byte, nbytes)
	_, _, _ = proc.Call(
		uintptr(unsafe.Pointer(&sig[0])),
		uintptr(len(sig)),
		uintptr(unsafe.Pointer(&msg[0])),
		uintptr(len(msg)),
		uintptr(unsafe.Pointer(&privatekey[0])),
		uintptr(len(privatekey)),
		uintptr(unsafe.Pointer(ctx)),
		uintptr(ctxlen),
		uintptr(unsafe.Pointer(stringToCharPtr(params))),
		uintptr(flags))

	return sig, nil
}

// Verify a DSA signature: default options, no context
//
// Returns true if the signature is valid over the message, else false. Returns a non-nil err if a parameter is wrong.
func (d Dsa) Verify(alg DsaAlg, sig []byte, msg []byte, publickey []byte) (ok bool, err error) {
	// long __stdcall DSA_Verify(const unsigned char *lpSignature, long nSigLen, const unsigned char *lpMsg, long nMsgLen,
	//	const unsigned char *lpPublicKey, long nKeyLen, const unsigned char *lpContext, long nCtxLen, const char *szParams, long nOptions);
	const _SIGNATURE_ERROR = -22
	var proc = syscall.NewLazyDLL(dllName).NewProc("DSA_Verify")
	flags := int(alg)
	ret, _, _ := proc.Call(0, 0,
		uintptr(unsafe.Pointer(&sig[0])),
		uintptr(len(sig)),
		uintptr(unsafe.Pointer(&msg[0])),
		uintptr(len(msg)),
		uintptr(unsafe.Pointer(&publickey[0])),
		uintptr(len(publickey)),
		uintptr(unsafe.Pointer(nil)),
		uintptr(0),
		uintptr(unsafe.Pointer(stringToCharPtr(""))),
		uintptr(flags))
	if int(ret) == _SIGNATURE_ERROR {
		// Signature is not valid
		return false, nil
	}
	if int(ret) < 0 {
		// Some other error, e.g. wrong parameter lengths
		return false, errors.New(errorLookup(int(ret)))
	}

	return true, nil
}

// Vaerify a DSA signature over a message. Extended options.
func (d Dsa) VerifyEx(alg DsaAlg, sig []byte, msg []byte, publickey []byte, opts SigOpts, context []byte) (ok bool, err error) {
	// long __stdcall DSA_Verify(const unsigned char *lpSignature, long nSigLen, const unsigned char *lpMsg, long nMsgLen,
	//	const unsigned char *lpPublicKey, long nKeyLen, const unsigned char *lpContext, long nCtxLen, const char *szParams, long nOptions);
	const _SIGNATURE_ERROR = -22
	var proc = syscall.NewLazyDLL(dllName).NewProc("DSA_Verify")
	flags := int(alg) | int(opts)
	var ctx *byte
	var ctxlen int
	if len(context) == 0 || context == nil {
		ctx = nil
		ctxlen = 0
	} else {
		ctx = &context[0]
		ctxlen = len(context)
	}
	ret, _, _ := proc.Call(
		uintptr(unsafe.Pointer(&sig[0])),
		uintptr(len(sig)),
		uintptr(unsafe.Pointer(&msg[0])),
		uintptr(len(msg)),
		uintptr(unsafe.Pointer(&publickey[0])),
		uintptr(len(publickey)),
		uintptr(unsafe.Pointer(ctx)),
		uintptr(ctxlen),
		uintptr(unsafe.Pointer(stringToCharPtr(""))),
		uintptr(flags))
	if int(ret) == _SIGNATURE_ERROR {
		return false, nil
	}
	if int(ret) < 0 {
		return false, errors.New(errorLookup(int(ret)))
	}

	return true, nil
}

// Extract the public key from a private key
func (d Dsa) PublicKeyFromPrivate(alg DsaAlg, sk []byte) (pk []byte, err error) {
	//long DSA_PublicKeyFromPrivate (unsigned char *lpOutput, long nOutBytes, const unsigned char *lpPrivateKey, long nKeyLen, long nAlg)
	var proc = syscall.NewLazyDLL(dllName).NewProc("DSA_PublicKeyFromPrivate")
	flags := int(alg)
	nbytes, _, _ := proc.Call(
		0, 0,
		uintptr(unsafe.Pointer(&sk[0])),
		uintptr(len(sk)),
		uintptr(flags))
	if int(nbytes) < 0 {
		return pk, errors.New(errorLookup(int(nbytes)))
	}
	pk = make([]byte, nbytes)
	_, _, _ = proc.Call(
		uintptr(unsafe.Pointer(&pk[0])),
		uintptr(len(pk)),
		uintptr(unsafe.Pointer(&sk[0])),
		uintptr(len(sk)),
		uintptr(flags))

	return pk, nil
}

// ///////////////
// KEM
// ///////////////

// KemAlg enumerates the available KEM algroithms
type KemAlg int

const (
	ML_KEM_512  KemAlg = 0x10 // ML_KEM_512 from FIPS.203 (based on Kyber512)
	ML_KEM_768  KemAlg = 0x11 // ML_KEM_768 from FIPS.203 (based on Kyber768)
	ML_KEM_1024 KemAlg = 0x12 // ML_KEM_1024 from FIPS.203 (based on Kyber1024)
)

// Lookup table
var algKemByString = map[string]KemAlg{
	"ML-KEM-512":  ML_KEM_512,
	"ML-KEM-768":  ML_KEM_768,
	"ML-KEM-1024": ML_KEM_1024,
}

// Kem provides methods to generate KEM keys, and perform key encapsulation and decapsulation.
type Kem struct{}

// Get the algorithm code from its name.
//
// NB case sensitive, expects dash "-" not underscore
func (k Kem) LookupAlgByName(s string) (alg KemAlg, err error) {
	alg, found := algKemByString[s]
	if !found {
		return alg, fmt.Errorf("%s does not match a valid KEM algorithm", s)
	}
	return alg, nil
}

// Get the algorithm name from its code
func (k Kem) AlgName(alg KemAlg) string {
	// long	PQC_AlgName (char *szOutput, long nOutChars, long nOptions)
	var proc = syscall.NewLazyDLL(dllName).NewProc("PQC_AlgName")
	flags := int(alg)
	nchars, _, _ := proc.Call(0, 0, uintptr(flags))
	buf := make([]byte, nchars+1)
	nchars, _, _ = proc.Call(
		uintptr(unsafe.Pointer(&buf[0])), nchars, uintptr(flags))
	outstr := string(buf[:nchars])
	return outstr
}

func kem_encapkeysize(alg KemAlg) int {
	// long __stdcall KEM_PublicKeySize(long nAlg);
	var proc = syscall.NewLazyDLL(dllName).NewProc("KEM_EncapKeySize")
	ret, _, _ := proc.Call(uintptr(alg))
	return int(ret)
}

// Return length in bytes of the encapsulation ("public") key `ek` for the KEM algorithm `KemAlg`
func (k Kem) EncapKeySize(alg KemAlg) int {
	return kem_encapkeysize(alg)
}

func kem_decapkeysize(alg DsaAlg) int {
	// long	KEM_DecapKeySize (long nAlg)
	var proc = syscall.NewLazyDLL(dllName).NewProc("KEM_DecapKeySize")
	ret, _, _ := proc.Call(uintptr(alg))
	return int(ret)
}

// Return length in bytes of expanded decapsulation key ("private key") for the given KEM algorithm.
func (k Kem) DecapKeySize(alg DsaAlg) int {
	return kem_decapkeysize(alg)
}

func kem_sharedkeysize(alg KemAlg) int {
	// long	KEM_SharedKeySize (long nAlg)
	var proc = syscall.NewLazyDLL(dllName).NewProc("KEM_SharedKeySize")
	ret, _, _ := proc.Call(uintptr(alg))
	return int(ret)
}

// Return length in bytes of the shared key (ss, K) for the given KEM algorithm.
func (k Kem) SharedKeySize(alg KemAlg) int {
	return kem_sharedkeysize(alg)
}

func kem_ciphertextsize(alg KemAlg) int {
	// long	KEM_CipherTextSize (long nAlg)
	var proc = syscall.NewLazyDLL(dllName).NewProc("KEM_CipherTextSize")
	ret, _, _ := proc.Call(uintptr(alg))
	return int(ret)
}

// Return length in bytes of ciphertext (ct, C) for the given KEM algorithm.
func (k Kem) CipherTextSize(alg KemAlg) int {
	return kem_ciphertextsize(alg)
}

// Generate an encapsulation/decapsulation key pair (ek, dk)<--KeyGen()
func (k Kem) KeyGen(alg KemAlg) (ek []byte, dk []byte, err error) {
	// long __stdcall KEM_KeyGen(unsigned char *lpOutput, long nOutBytes, const char *szParams, long nOptions);
	var proc = syscall.NewLazyDLL(dllName).NewProc("KEM_KeyGen")
	flags := int(alg)
	nbytes, _, _ := proc.Call(
		0, 0, uintptr(unsafe.Pointer(stringToCharPtr(""))), uintptr(flags))
	if int(nbytes) < 0 {
		return ek, dk, errors.New(errorLookup(int(nbytes)))
	}
	buf := make([]byte, nbytes)
	_, _, _ = proc.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		nbytes,
		uintptr(unsafe.Pointer(stringToCharPtr(""))),
		uintptr(flags))
	// Split pk||sk
	eklen := kem_encapkeysize(alg)
	ek = buf[:eklen]
	dk = buf[eklen:]

	return ek, dk, nil
}

// Generate an encapsulation/decapsulation key pair passing known randomness encoded in hex
func (k Kem) KeyGenWithParams(alg KemAlg, params string) (ek []byte, dk []byte, err error) {
	// long __stdcall KEM_KeyGen(unsigned char *lpOutput, long nOutBytes, const char *szParams, long nOptions);
	var proc = syscall.NewLazyDLL(dllName).NewProc("KEM_KeyGen")
	flags := int(alg)
	nbytes, _, _ := proc.Call(
		0, 0, uintptr(unsafe.Pointer(stringToCharPtr(params))), uintptr(flags))
	if int(nbytes) < 0 {
		return ek, dk, errors.New(errorLookup(int(nbytes)))
	}
	buf := make([]byte, nbytes)
	_, _, _ = proc.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		nbytes,
		uintptr(unsafe.Pointer(stringToCharPtr(params))),
		uintptr(flags))
	// Split pk||sk
	eklen := kem_encapkeysize(alg)
	ek = buf[:eklen]
	dk = buf[eklen:]

	return ek, dk, nil
}

// Carry out the ML-KEM encapsulation algorithm: (ct,ss)<--Encaps(ek)
func (k Kem) Encaps(alg KemAlg, ek []byte) (ct []byte, ss []byte, err error) {
	// long	KEM_Encaps (unsigned char *lpOutput, long nOutBytes, const unsigned char *lpEncapKey,
	//    long nEncapKeyLen, const char *szParams, long nOptions)
	var proc = syscall.NewLazyDLL(dllName).NewProc("KEM_Encaps")
	//fmt.Println(alg)
	flags := int(alg)
	nbytes, _, _ := proc.Call(0, 0,
		uintptr(unsafe.Pointer(&ek[0])),
		uintptr(len(ek)),
		uintptr(unsafe.Pointer(stringToCharPtr(""))),
		uintptr(flags))
	if int(nbytes) < 0 {
		return ct, ss, errors.New(errorLookup(int(nbytes)))
	}
	buf := make([]byte, nbytes)
	_, _, _ = proc.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		nbytes,
		uintptr(unsafe.Pointer(&ek[0])),
		uintptr(len(ek)),
		uintptr(unsafe.Pointer(stringToCharPtr(""))),
		uintptr(flags))
	// Output is ss||ct as a concatenated pair of byte arrays
	// Split ss||ct - NB ss is first
	sslen := kem_sharedkeysize(alg)
	ss = buf[:sslen]
	ct = buf[sslen:]
	return ct, ss, nil
}

// Carry out the ML-KEM encapsulation algorithm: (ct,ss)<--Encaps(ek)
//   - Use "params" to pass a known test random seed encoded in hex and representing exactly 32 bytes.
func (k Kem) EncapsWithParams(alg KemAlg, ek []byte, params string) (ct []byte, ss []byte, err error) {
	// long	KEM_Encaps (unsigned char *lpOutput, long nOutBytes, const unsigned char *lpEncapKey, long nEncapKeyLen, const char *szParams, long nOptions)
	var proc = syscall.NewLazyDLL(dllName).NewProc("KEM_Encaps")
	//fmt.Println(alg)
	flags := int(alg)
	nbytes, _, _ := proc.Call(0, 0,
		uintptr(unsafe.Pointer(&ek[0])),
		uintptr(len(ek)),
		uintptr(unsafe.Pointer(stringToCharPtr(params))),
		uintptr(flags))
	if int(nbytes) < 0 {
		return ct, ss, errors.New(errorLookup(int(nbytes)))
	}
	buf := make([]byte, nbytes)
	_, _, _ = proc.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		nbytes,
		uintptr(unsafe.Pointer(&ek[0])),
		uintptr(len(ek)),
		uintptr(unsafe.Pointer(stringToCharPtr(params))),
		uintptr(flags))
	// Output is ss||ct as a concatenated pair of byte arrays
	// Split ss||ct - NB ss is first
	sslen := kem_sharedkeysize(alg)
	ss = buf[:sslen]
	ct = buf[sslen:]
	return ct, ss, nil
}

// Carry out the ML-KEM decapsulation algorithm: (ss')<--Decaps(ct, dk)
func (k Kem) Decaps(alg KemAlg, ct []byte, dk []byte) (ss []byte, err error) {
	// long	KEM_Decaps (unsigned char *lpOutput, long nOutBytes, const unsigned char *lpCipherText,
	//    long nCipherTextLen, const unsigned char *lpDecapKey, long nDecapKeyLen, const char *szParams, long nOptions)
	var proc = syscall.NewLazyDLL(dllName).NewProc("KEM_Decaps")
	//fmt.Println(alg)
	flags := int(alg)
	nbytes, _, _ := proc.Call(0, 0,
		uintptr(unsafe.Pointer(&ct[0])),
		uintptr(len(ct)),
		uintptr(unsafe.Pointer(&dk[0])),
		uintptr(len(dk)),
		uintptr(unsafe.Pointer(stringToCharPtr(""))),
		uintptr(flags))
	if int(nbytes) < 0 {
		return ss, errors.New(errorLookup(int(nbytes)))
	}
	ss = make([]byte, nbytes)
	_, _, _ = proc.Call(
		uintptr(unsafe.Pointer(&ss[0])),
		nbytes,
		uintptr(unsafe.Pointer(&ct[0])),
		uintptr(len(ct)),
		uintptr(unsafe.Pointer(&dk[0])),
		uintptr(len(dk)),
		uintptr(unsafe.Pointer(stringToCharPtr(""))),
		uintptr(flags))
	return ss, nil
}
