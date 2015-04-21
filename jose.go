// Package jose provides a suite of utilities to implement a variant of the JWT spec, see [https://github.com/vizidrix/jsoe/readme.md for more details
package jose

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
)

var (
	ErrNotImplemented        = errors.New("not yet implemented")
	ErrClaimOverwritten      = errors.New("cannot overwrite a claim that was previously set")
	ErrInvalidFormat         = errors.New("unable to parse data structure")
	ErrEmptyToken            = errors.New("cannot validate an empty token")
	ErrInvalidAlgorithm      = errors.New("unable to use provided algorithm")
	ErrInvalidKeyOps         = errors.New("unable to use provide key operations")
	ErrEncodeInvalidToken    = errors.New("cannot encode invalid token")
	ErrDecodeInvalidToken    = errors.New("cannot decode invalid token")
	ErrUnitializedToken      = errors.New("uninitialized token cannot be used")
	ErrRequiredElementWasNil = errors.New("required token def element was nil")
)

const period = 46
const equals = 61

var period_slice = []byte{'.'}
var equals_slice = []byte{'='}

var base64_padding = map[int][]byte{
	0: []byte{},
	1: bytes.Repeat(equals_slice, 1),
	2: bytes.Repeat(equals_slice, 2),
	3: bytes.Repeat(equals_slice, 3),
}

const ( // https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-4.1.9
	JOSE_JWT      = "JWT"
	JOSE_JWT_JSON = "JWT+JSON"
	JOSE_JWE      = "JWE"
	JOSE_JWE_JSON = "JWE+JSON"
	JOSE_JWK      = "JWK"
	JOSE_JWK_JSON = "JWK+JSON"
)

// See Key Definition Guidelines in readme for important considerations

// Use and Ops serve similar purposes, valid configs are enforced unless disabled
// Available properties for the "use" property of a JWK
// Available properties for the "key_ops" property of a JWK
type JWKKeyOps int64

const (
	Ops_NoCheck    JWKKeyOps = 1 << iota // Disable validation on key ops config
	Ops_Use_Sig                          // Key is the Signature of the correlated data
	Ops_Use_Enc                          // Key was used to encrypt the correlated data
	Ops_Sign                             // Compute digital signature or MAC
	Ops_Verify                           // Verify digital signature or MAC
	Ops_Encrypt                          // Encrypt content
	Ops_Decrypt                          // Decrypt content and validate the decryption, if applicable
	Ops_WrapKey                          // Encrypts a key
	Ops_UnwrapKey                        // Decrypt key and validate decryption, if applicable
	Ops_DeriveKey                        // Derive key
	Ops_DeriveBits                       // Derive bits not to be used as a key
	// Ops combinations
	OpsCombo_SignVerify       = Ops_Sign | Ops_Verify
	OpsCombo_EncryptDecrypt   = Ops_Encrypt | Ops_Decrypt
	OpsCombo_WrapKeyUnwrapKey = Ops_WrapKey | Ops_UnwrapKey
	// Ops / Use combinations...
	//Ops_Use_Sign
	// Ops Categories
	Ops_Cat_Sign    = Ops_Use_Sig | Ops_Sign | Ops_Verify
	Ops_Cat_Encrypt = Ops_Use_Enc | Ops_Encrypt | Ops_Decrypt | Ops_WrapKey | Ops_UnwrapKey
)

var OpsMap = map[JWKKeyOps]string{
	Ops_Sign:       "sign",
	Ops_Verify:     "verify",
	Ops_Encrypt:    "encrypt",
	Ops_Decrypt:    "decrypt",
	Ops_WrapKey:    "wrapKey",
	Ops_UnwrapKey:  "unwrapKey",
	Ops_DeriveKey:  "deriveKey",
	Ops_DeriveBits: "deriveBits",
}

func CheckOps(v JWKKeyOps, ops ...JWKKeyOps) bool {
	for _, o := range ops {
		if v&o != o { // If any fail to match then reject the check
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

type WebKeySet struct {
	WebKeyDef
	Keys []WebKeyDef `json:"keys,omitempty"` // Required parameter containing an array of uinque (KID+KTY) JWK keys
}

// Header rovides members to describe the meta-data and protection for the payload and carry more visible processing data
// per spec: https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-4
type HeaderDef struct { // https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-4.1
	Type          string                 `json:"typ,omitempty"`    // MIME Media Type [IANA.MediaTypes] of this complete JWS
	ContentType   string                 `json:"cty,omitempty"`    // MIME Media Type [IANA.MediaTypes] of the secured content (the payload)
	Algorithm     string                 `json:"alg,omitempty"`    // The Signing / Encryption algorithm used on this token
	PublicParams  map[string]interface{} `json:"pub,omitempty"`    // Public header params should respect existing published params or be reasonably in control of the namespace
	PrivateParams map[string]interface{} `json:"pri,omitempty"`    // Private header params are unrestricted but should be understood by both producers and consumers
	PublicClaims  map[string]interface{} `json:"claims,omitempty"` // Map of keyed claims to include if provided, must be duplicated in and validated against matching claims in the payload
	JSONWebKey    *WebKeySet             `json:"jwk,omitempty"`    // JWK encoded JSON web key rleated to this token
	JSONWebKeyUri string                 `json:"jku,omitempty"`    // Uri location of JWK encoded public key related to this token, must be TLS
	JSONWebKeyId  string                 `json:"kid,omitempty"`    // Value used to identify the key used to validating entity (when paired with Uri can identify item from set)

	// TODO: Implement checks for critical params
	//Critical      []string               `json:"crit,omitempty"`    // Indicates extensions to the spec that must be understood and respected if presented: https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-4.1.11

	// TODO: Implement certificate support features
	//X509Header string `json:"x5u,omitmepty"` // Uri location of the X.509 public key
	//X509CertChain []string `json:"x5c"` // Public key or cert chain of the cert used on the token: https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-4.1.6
	//X509SHA1 string `json:"x5t,omitempty"` // Base64 encoded DER encoding of an X.509 Certificate using SHA-1
	//X509SHA256 string `json:"x5t#S256"` // Base64 encoded DER encoding of an X.509 Certificate using SHA-256
}

// PayloadDef is used to describe the set of properties that can be encoded in the body of the token
// per spec: https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-08#section-1
type PayloadDef struct {
	Id             string                 `json:"jid,omitempty"`    // The UID for the JOSE payload to identify the data between parties
	ExpirationTime int64                  `json:"exp,omitempty"`    // UTC Unix time at which the token should no longer be excepted
	NotBefore      int64                  `json:"nbf,omitempty"`    // UTC Unix time before whtich the token should not be accepted for processing
	IssuedAtTime   int64                  `json:"iat,omitempty"`    // UTC Unix time at which the token was issued
	Issuer         string                 `json:"iss,omitempty"`    // The issuer of the claim or app which requested the token
	Audience       string                 `json:"aud,omitempty"`    // The aucience(s) of the token which can be used to identify intended recipients
	Tenant         string                 `json:"ten,omitempty"`    // The UID for the tenant of the issuing app
	Subject        string                 `json:"sub,omitempty"`    // The UID for the subject of the token which identifies the current user, if authenticated
	Principal      string                 `json:"prn,omitempty"`    // Legacy name of the property now called Subject
	Nonce          string                 `json:"non,omitempty"`    // A randomized nonce can be provided to ensure that hashes are not spoofable by replays for more static payloads
	Data           interface{}            `json:"dat,omitempty"`    // Custom payload data to include if provided
	PrivateClaims  map[string]interface{} `json:"claims,omitempty"` // Map of keyed claims to include if provided
}

// WebKeyReader provides access to read/only properties and methods of a web key definition
// Any reference data should be obfuscated to ensure against unintentional or invalid modification
type WebKeyReader interface {
	GetKeyType() string
	GetPubilcKeyUse() string
	GetKeyOperations() string
	GetAlgorithm() string
	GetKeyId() string
	GetX509Url() string
	GetX509CertChain() []string
	GetX509_SHA1() string
	GetX509_SHA256() string
}

// HeaderReader provides access to read/only properties and methods of a token's header
// Any reference data should be obfuscated to ensure against unintentional or invalid modification
type HeaderReader interface {
	EncodeHeader(io.Writer) error
	GetHeader() (HeaderDef, error)
	GetType() string
	GetAlgorithm() string
	GetPublicParams() (map[string]interface{}, error)
	GetPrivateParams() (map[string]interface{}, error)
	GetPublicClaims() (map[string]interface{}, error)
	GetWebKeys() []WebKeyReader
}

// PayloadReader provides access to read/only properties and methods of a token's payload
// Any reference data should be obfuscated to ensure against unintentional or invalid modification
type PayloadReader interface {
	EncodePayload(io.Writer) error
	GetPayload() (PayloadDef, error)
	GetId() string
	GetExpirationTime() int64
	GetNotBefore() int64
	GetIssuedAtTime() int64
	GetIssuer() string
	GetAudience() string
	GetTenant() string
	GetSubject() string
	GetPrincipal() string
	GetNonce() string
	GetData() (interface{}, error)
	GetPrivateClaims() (map[string]interface{}, error)
}

// TokenReader provides a unified wrapper over a token's internal structures
type TokenReader interface {
	HeaderReader
	PayloadReader
	Encode() ([]byte, error)
	Validate() []error
}

// TokenModifier is the signature of the function which can be used to modify a TokenDef
type TokenModifier func(*TokenDef) error

// KeyModifier is the signature of a function which can be used to modifiy a WebKeyDef
type KeyModifier func(*WebKeyDef) error

// ConstraintFlags alter the behavior of the token definition logic to provide configurable protection levels
type ConstraintFlags int64

const (
	None_Algo          ConstraintFlags                        = 1 << iota // Blocks the validator from passing a "none" algo definition
	Alg_Only                                                              // Block tokens that don't provide JWK entries for Keys (disable "alg" only by default, see security vulnerability in readme)
	Overwrite_Private                                                     // Blocks private claims from being overwritten by other subsequent updates to the same key
	Overwrite_Public                                                      // Blocks public claims from being overwritten by other subsequent updates to the same key
	Swap_Private                                                          // Blocks silent upgrading of private claims to public claims, risks exposing or discarding data intended to be private
	Swap_Public                                                           // Blocks silent downgrading of public claims to private claims, risks hiding data intended to be public
	Overwrites         = Overwrite_Private | Overwrite_Public             // Blocks both overwrite cases
	Swaps              = Swap_Private | Swap_Public                       // Blocks both swap cases
	OverwritesAndSwaps = Overwrites | Swaps                               // Blocks all claim related cases
	Strict             = None_Algo | OverwritesAndSwaps                   // Blocks all defined constraints, intended to provide the safest constraint option
	None               = 0                                                // Disables all constraints
)

type Settings struct {
	flags ConstraintFlags
}

func (s *Settings) UseConstraints(cf ...ConstraintFlags) {
	s.flags = None
	s.AddConstraints(cf...)
}
func (s *Settings) RemoveConstraints(cf ...ConstraintFlags) {
	for _, c := range cf {
		s.flags = s.flags ^ c
	}
}

func (s *Settings) AddConstraints(cf ...ConstraintFlags) {
	for _, c := range cf {
		s.flags = s.flags | c
	}
}

func (s *Settings) CheckConstraints(cf ...ConstraintFlags) bool {
	for _, c := range cf {
		if s.flags&c != c {
			return false
		}
	}
	return true
}

// Decode parses, validates and extracts the state of the token, returning an error if any part fails
func Decode(token []byte, mods ...TokenModifier) (r *TokenDef, err error) {
	t := NewEmptyToken()
	mods = append(mods, Load(token))
	t = t.Mod(mods...)
	errs := t.GetErrors()
	if errs != nil {
		if _, ok := t.errors[ErrInvalidAlgorithm]; ok {
			return nil, ErrInvalidAlgorithm
		}
		log.Printf("Decode [ %s ]", errs)
		return nil, ErrDecodeInvalidToken
	}
	return t, nil
}

func Encode(t *TokenDef) ([]byte, error) {
	if t.errors != nil {
		return nil, ErrEncodeInvalidToken
	}
	h := &bytes.Buffer{}
	if err := t.EncodeHeader(h); err != nil {
		return nil, err
	}
	p := &bytes.Buffer{}
	if err := t.EncodePayload(p); err != nil {
		return nil, err
	}
	s := &bytes.Buffer{}
	s.Write(bytes.TrimRight(h.Bytes(), "="))
	s.WriteByte(period)
	// Encrypt p prior to signing
	s.Write(bytes.TrimRight(p.Bytes(), "="))
	//log.Printf("SigData: [ %s ]", s.Bytes())

	s.WriteByte(period)
	// Append signature
	//log.Printf("Token: [ %s ]", s.Bytes())
	return s.Bytes(), nil
}

func json_decode_trimmed_base64(l int, d []byte, t interface{}) (err error) {
	m := l % 4
	b := bytes.NewBuffer(make([]byte, 0, l+m))
	b.Write(d)
	b.Write(base64_padding[m])
	r := base64.NewDecoder(base64.URLEncoding, b)
	j := json.NewDecoder(r)
	if err = j.Decode(t); err != nil {
		return err
	}
	return nil
}

func WrapErr(message string, err error) error {
	return errors.New(fmt.Sprintf("%s: [ %s ]", message, err))
}

func CloneMap(in map[string]interface{}) (map[string]interface{}, error) {
	var v map[string]interface{}
	if data, err := json.Marshal(in); err != nil {
		return nil, err
	} else {
		if err := json.Unmarshal(data, &v); err != nil {
			return nil, err
		}
	}
	return v, nil
}

func CloneInterface(in interface{}) (interface{}, error) {
	var v interface{}
	if data, err := json.Marshal(in); err != nil {
		return nil, err
	} else {
		if err := json.Unmarshal(data, &v); err != nil {
			return nil, err
		}
	}
	return v, nil
}
