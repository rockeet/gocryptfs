//go:build !without_openssl
// +build !without_openssl

package stupidgcm

// #include <openssl/evp.h>
import "C"

import (
	"crypto/cipher"
	//"fmt"
	//"os"
	"log"
	//"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

const (
	SM4KeyLen = 16
	sm4_ivLen  = 16
	sm4_tagLen = 16
)

// _EVP_chacha20_poly1305 caches C.EVP_chacha20_poly1305() to avoid the Cgo call
// overhead for each instantiation of NewChacha20poly1305.
var _EVP_sm4 *C.EVP_CIPHER
var algo_name = "SM4-GCM"

func init1() {
/*
// in openssl #include <prov/names.h> which defines:
//
#define PROV_NAMES_SM4_ECB "SM4-ECB:1.2.156.10197.1.104.1"
#define PROV_NAMES_SM4_CBC "SM4-CBC:SM4:1.2.156.10197.1.104.2"
#define PROV_NAMES_SM4_CTR "SM4-CTR:1.2.156.10197.1.104.7"
#define PROV_NAMES_SM4_OFB "SM4-OFB:SM4-OFB128:1.2.156.10197.1.104.3"
#define PROV_NAMES_SM4_CFB "SM4-CFB:SM4-CFB128:1.2.156.10197.1.104.4"
#define PROV_NAMES_SM4_GCM "SM4-GCM:1.2.156.10197.1.104.8"
#define PROV_NAMES_SM4_CCM "SM4-CCM:1.2.156.10197.1.104.9"
#define PROV_NAMES_SM4_XTS "SM4-XTS:1.2.156.10197.1.104.10"
*/
/*
	env := os.Getenv("CIPHER_ALGO_NAME")
	if len(env) > 0 {
		algo_name = env;
	}
*/
	var c_algo_name = C.CString(algo_name)
	_EVP_sm4 = C.EVP_CIPHER_fetch(nil, c_algo_name, nil);
	//fmt.Fprintf(os.Stderr, "init: _EVP_sm4 = %p, algo_name = %s\n", _EVP_sm4, algo_name)
	if _EVP_sm4 == nil {
		log.Panicf("C.EVP_CIPHER_fetch(%s) failed", algo_name)
	}
}

func init() {
	init1();
}

type sm4GCM struct {
	stupidAEADCommon
}

func NewSM4GCM(keyIn []byte) cipher.AEAD {
	if len(keyIn) != SM4KeyLen {
		log.Panicf("SM4: len(keyIn) = %d, Only %d-byte keys are supported", len(keyIn), SM4KeyLen)
	}
	return &sm4GCM{
		stupidAEADCommon{
			// Create a private copy of the key
			key:              append([]byte{}, keyIn...),
			openSSLEVPCipher: _EVP_sm4,
			nonceSize:        sm4_ivLen,
		},
	}
}
