package jose

import (
	"bytes"
	"fmt"
)

// See Key Definition Guidelines in readme for important considerations

// Use and Ops serve similar purposes, valid configs are enforced unless disabled
// Available properties for the "use" property of a JWK
// Available properties for the "key_ops" property of a JWK
type JWKKeyOpFlag int64

const (
	Ops_NoCheck    JWKKeyOpFlag = 1 << iota // Disable validation on key ops config
	Ops_Use_Sig                             // Key is the Signature of the correlated data
	Ops_Use_Enc                             // Key was used to encrypt the correlated data
	Ops_Sign                                // Compute digital signature or MAC
	Ops_Verify                              // Verify digital signature or MAC
	Ops_Encrypt                             // Encrypt content
	Ops_Decrypt                             // Decrypt content and validate the decryption, if applicable
	Ops_WrapKey                             // Encrypts a key
	Ops_UnwrapKey                           // Decrypt key and validate decryption, if applicable
	Ops_DeriveKey                           // Derive key
	Ops_DeriveBits                          // Derive bits not to be used as a key
	// Ops combinations
	Ops_Combo_SignVerify       = Ops_Sign | Ops_Verify
	Ops_Combo_EncryptDecrypt   = Ops_Encrypt | Ops_Decrypt
	Ops_Combo_WrapKeyUnwrapKey = Ops_WrapKey | Ops_UnwrapKey
	// Ops / Use combinations...
	//Ops_Use_Sign
	// Ops Categories
	Ops_Cat_Sign    = Ops_Use_Sig | Ops_Sign | Ops_Verify
	Ops_Cat_Encrypt = Ops_Use_Enc | Ops_Encrypt | Ops_Decrypt | Ops_WrapKey | Ops_UnwrapKey
)

var OpsMap = map[JWKKeyOpFlag]string{
	Ops_Sign:       "sign",
	Ops_Verify:     "verify",
	Ops_Encrypt:    "encrypt",
	Ops_Decrypt:    "decrypt",
	Ops_WrapKey:    "wrapKey",
	Ops_UnwrapKey:  "unwrapKey",
	Ops_DeriveKey:  "deriveKey",
	Ops_DeriveBits: "deriveBits",
}

func GetOps(f JWKKeyOpFlag) []string {
	ops := make([]string, 0)
	for k, v := range OpsMap {
		if f&k == k { // Found mathing op map entry
			ops = append(ops, v)
		}
	}
	return ops
}

func CheckOps(f JWKKeyOpFlag, ops ...JWKKeyOpFlag) bool {
	for _, o := range ops {
		if f&o != o { // If any fail to match then reject the check
			return false
		}
	}
	return true
}

// Reserved keys should not be allowed in
const Reserved = `kty|use|key_ops|alg|kid|x5u|x5c|x5t|x5t#256|keys|typ|cty|pub|pri|claims|jwk|jku|kid|jid|exp|nbf|iat|iss|aud|ten|sub|prn|non|dat`

// WebKeyDef is used to describe the crypto method used to protect the JWS element
// per spec: https://tools.ietf.org/html/draft-ietf-jose-json-web-key-41
type WebKeyDef struct {
	KeyType       string   `json:"kty,omitempty"`     // Identifies the cryptographic algorithm family used with the key, such as "RSA" or "EC"
	PublicKeyUse  string   `json:"use,omitempty"`     // Indicates whether a public key is used for encrypting data or verifying the signature on data
	KeyOperations []string `json:"key_ops,omitempty"` // Defines which operations the key was intended for use in - as an arrry per: https://tools.ietf.org/html/draft-ietf-jose-json-web-key-31#section-8.3
	Algorithm     string   `json:"alg,omitempty"`     // Identifies the algorithm intended for use with the key
	KeyId         string   `json:"kid,omitempty"`     // Identifies a key within a set, for ex during rollover scenarios
	X509Url       string   `json:"x5u,omitempty"`     // Refers to a resource for an X.509 public key cert or cert chain
	X509CertChain []string `json:"x5c,omitempty"`     // Contains a chain of one or more PKIX certs as a JSON array of cert value strings in verify order
	X509_SHA1     string   `json:"x5t,omitempty"`     // Base64Url encoded SHA-1 thumprint of the DER encoding of an X.509 certificate
	X509_SHA256   string   `json:"x5t#256,omitempty"` // Base64Url encoded SHA-256 thumbprint of the DER encoding of an X.509 certificate
}

func (k WebKeyDef) GetKeyType() string {
	return k.KeyType
}

func (k WebKeyDef) GetPubilcKeyUse() string {
	return k.PublicKeyUse
}

func (k WebKeyDef) GetKeyOperations() []string {
	l := len(k.KeyOperations)
	r := make([]string, l, l)
	copy(r, k.KeyOperations)
	return r
}

func (k WebKeyDef) GetAlgorithm() string {
	return k.Algorithm
}

func (k WebKeyDef) GetKeyId() string {
	return k.KeyId
}

func (k WebKeyDef) GetX509Url() string {
	return k.X509Url
}

func (k WebKeyDef) GetX509CertChain() []string {
	l := len(k.X509CertChain)
	r := make([]string, l, l)
	copy(r, k.X509CertChain)
	return r
}

func (k WebKeyDef) GetX509_SHA1() string {
	return k.X509_SHA1
}

func (k WebKeyDef) GetX509_SHA256() string {
	return k.X509_SHA256
}

type WebKeySetDef struct {
	WebKeyDef
	Keys []WebKeyDef `json:"keys,omitempty"` // Required parameter containing an array of uinque (KID+KTY) JWK keys
}

func NewWebKeySet(defs ...WebKeyDef) WebKeySetDef {
	l := len(defs)
	if l == 1 {
		return WebKeySetDef{
			WebKeyDef: defs[0],
		}
	}
	r := WebKeySetDef{
		Keys: make([]WebKeyDef, l, l),
	}
	for i, def := range defs {
		r.Keys[i] = def
	}
	return r
}

func (k WebKeyDef) String() string {
	b := bytes.NewBufferString("\n{{ JWK:\n")

	write_prop(b, "Key Type", k.KeyType)
	write_prop(b, "Key Use", k.PublicKeyUse)
	for i, op := range k.KeyOperations {
		write_prop(b, fmt.Sprintf("[ %d ]", i), op)
	}
	write_prop(b, "Algorithm", k.Algorithm)
	write_prop(b, "Key Id", k.KeyId)
	write_prop(b, "x509 Url", k.X509Url)
	for i, cert := range k.X509CertChain {
		write_prop(b, fmt.Sprintf("[ %d ]", i), cert)
	}
	write_prop(b, "x509 SHA1", k.X509_SHA1)
	write_prop(b, "x509 SHA256", k.X509_SHA256)
	write_json(b, "Web Key", k)

	b.WriteString("}}\n")
	return b.String()
}
