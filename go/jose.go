// Package jose provides a suite of utilities to implement a variant of the JWT spec, see [https://github.com/vizidrix/jsoe/readme.md for more details
package jose

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"time"
)

var (
	ErrClaimOverwritten      = errors.New("cannot overwrite a claim that was previously set")
	ErrInvalidFormat         = errors.New("unable to parse data structure")
	ErrEmptyToken            = errors.New("cannot validate an empty token")
	ErrInvalidAlgorithm      = errors.New("unable to use provided algorithm")
	ErrEncodeInvalidToken    = errors.New("cannot encode invalid token")
	ErrDecodeInvalidToken    = errors.New("cannot decode invalid token")
	ErrUnitializedToken      = errors.New("uninitialized token cannot be used")
	ErrRequiredElementWasNil = errors.New("required token def element was nil")
)

const period = 46

var period_slice = []byte{'.'}

const ( // https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-4.1.9
	JOSE_JWT      = "JWT"
	JOSE_JWT_JSON = "JWT+JSON"
	JOSE_JWE      = "JWE"
	JOSE_JWE_JSON = "JWE+JSON"
	JOSE_JWK      = "JWK"
	JOSE_JWK_JSON = "JWK+JSON"
)

// WebKeyDef is used to describe the crypto method used to protect the JWS element
// per spec: https://tools.ietf.org/html/draft-ietf-jose-json-web-key-41
type WebKeyDef struct {
	KeyType       string `json:"kty"`
	PublicKeyUse  string `json:"use"`
	KeyOperations string `json:"key_ops"`
	Algorithm     string `json:"alg"`
}

// Header rovides members to describe the meta-data and protection for the payload and carry more visible processing data
// per spec: https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-4
type HeaderDef struct { // https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-4.1
	Type          string                 `json:"typ,omitempty"`     // The "typ" (type) Header Parameter is used by JWS applications to declare the MIME Media Type [IANA.MediaTypes] of this complete JWS
	ContentType   string                 `json:"cty,omitempty"`     // The "cty" (content type) Header Parameter is used by JWS applications to declare the MIME Media Type [IANA.MediaTypes] of the secured content (the payload)
	Algorithm     string                 `json:"alg,omitempty"`     // The Signing / Encryption algorithm used on this token
	PublicParams  map[string]interface{} `json:"public,omitempty"`  // Public header params should respect existing published params or be reasonably in control of the namespace
	PrivateParams map[string]interface{} `json:"private,omitempty"` // Private header params are unrestricted but should be understood by both producers and consumers
	PublicClaims  map[string]interface{} `json:"claims,omitempty"`  // Map of keyed claims to include if provided, must be duplicated in and validated against matching claims in the payload
	//Critical      []string               `json:"crit,omitempty"`    // Indicates extensions to the spec that must be understood and respected if presented: https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-4.1.11
	//JSONWebKey    string                 `json:"jwk,omitempty"`     // JWK encoded JSON web key rleated to this token
	//JSONWebKeyUri string                 `json:"jku,omitempty"`     // Uri location of JWK encoded public key related to this token, must be TLS
	//JSONWebKeyId  string                 `json:"kid,omitempty"`     // Value used to identify the key used to validating entity (when paired with Uri can identify item from set)

	// TODO: Implement certificate support features
	//X509Header string `json:"x5u,omitmepty"` // Uri location of the X.509 public key
	//X509CertChain string `json:"x5c"` // Public key or cert chain of the cert used on the token: https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-4.1.6
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
	Nonce          string                 `json:"nonce,omitempty"`  // A randomized nonce can be provided to ensure that hashes are not spoofable by replays for more static payloads
	Data           interface{}            `json:"data,omitempty"`   // Custom payload data to include if provided
	PrivateClaims  map[string]interface{} `json:"claims,omitempty"` // Map of keyed claims to include if provided
}

// WebKeyReader provides access to read/only properties and methods of a web key definition
// Any reference data should be obfuscated to ensure against unintentional or invalid modification
type WebKeyReader interface {
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

// TokenModifier is the signature of the function lifted to apply changes to the token monad
type TokenModifier func(*TokenDef) error

// ConstraintFlags alter the behavior of the token definition logic to provide configurable protection levels
type ConstraintFlags int64

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

const (
	None_Algo          ConstraintFlags                        = 1 << iota // Blocks the validator from passing a "none" algo definition
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

const TenMinutes = 10 * time.Minute

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

func New(mods ...TokenModifier) *TokenDef {
	return NewEmptyToken().Mod(mods...)
}

/*
func HMAC256(secret string) TokenModifier {
	return func(t *TokenDef) error {
		return nil
	}
}
*/

func Load(token []byte) TokenModifier {
	return func(t *TokenDef) error {
		segs := bytes.Split(token, period_slice)
		if len(segs) != 3 {
			log.Printf("Seg Count [ %s ]", segs)
			return ErrDecodeInvalidToken
		}
		h_len := len(segs[0])
		p_len := len(segs[1])
		d := token[:h_len+p_len+1]
		log.Printf("\n\tT [ %s ] -> [ %d / %d ]\n\tData: [ %s ]\n", token, h_len, p_len, d)
		s_len := len(segs[2])
		if s_len == 0 { // None signature
			if t.settings.CheckConstraints(None_Algo) { // Require explicit acceptance
				return ErrInvalidAlgorithm
			}
		}
		return nil
	}
}

/*
func Load2(token []byte) TokenModifier {
	return func(t *TokenDef) error {
		token_len := len(token)
		data_len := bytes.LastIndex(token, period_slice)
		//sig_len := token_len - data_len
		//sig := make([]byte, 0, sig_len)
		//data := make([]byte, 0, data_len)
		log.Printf("\n* Load:\n[ %d ]\n[ %d ]\n\n", token_len, data_len)
		if data_len < 0 { // Didn't find signature period
			return ErrDecodeInvalidToken
		}
		if data_len > token_len { // Bounds check
			return ErrDecodeInvalidToken
		}
		data := token[:data_len]
		sig := token[data_len+1:]
		// Verify signature
		header_len := bytes.Index(data, period_slice)
		if header_len < 0 { // Didn't find header period

		}
		payload_len := data_len - header_len

		header := data[:header_len]
		payload := data[header_len+1:]

		log.Printf("\n* Load:\n[ %s ]\n[ %s ]\n\n", data, sig)
		return nil
	}
}
*/

func UseConstraints(cs ...ConstraintFlags) TokenModifier {
	return func(t *TokenDef) error {
		if t == nil || t.settings == nil {
			return ErrRequiredElementWasNil
		}
		t.settings.UseConstraints(cs...)
		return nil
	}
}
func RemoveConstraints(cs ...ConstraintFlags) TokenModifier {
	return func(t *TokenDef) error {
		if t == nil || t.settings == nil {
			return ErrRequiredElementWasNil
		}
		t.settings.RemoveConstraints(cs...)
		return nil
	}
}

func AddConstraints(cs ...ConstraintFlags) TokenModifier {
	return func(t *TokenDef) error {
		if t == nil || t.settings == nil {
			return ErrRequiredElementWasNil
		}
		t.settings.AddConstraints(cs...)
		return nil
	}
}

func Id(id string) TokenModifier {
	return func(t *TokenDef) error {
		if t == nil || t.payload == nil {
			return ErrRequiredElementWasNil
		}
		t.payload.Id = id
		return nil
	}
}

func PrivateClaims(private map[string]interface{}) TokenModifier {
	return func(t *TokenDef) error {
		if t == nil || t.settings == nil || t.header == nil || t.payload == nil {
			return ErrRequiredElementWasNil
		}
		for k, v := range private {
			if t.settings.CheckConstraints(Overwrite_Private) {
				if _, ok := t.payload.PrivateClaims[k]; ok {
					return ErrClaimOverwritten
				}
			}
			if _, ok := t.header.PublicClaims[k]; ok {
				if t.settings.CheckConstraints(Swap_Public) {
					return ErrClaimOverwritten
				} // Overwrie allowed so remove it from public set
				delete(t.header.PublicClaims, k)
			}
			t.payload.PrivateClaims[k] = v
		}
		return nil
	}
}

func PublicClaims(public map[string]interface{}) TokenModifier {
	return func(t *TokenDef) error {
		if t == nil || t.settings == nil || t.header == nil || t.payload == nil {
			return ErrRequiredElementWasNil
		}
		for k, v := range public {
			if t.settings.CheckConstraints(Overwrite_Public) {
				if _, ok := t.header.PublicClaims[k]; ok {
					return ErrClaimOverwritten
				}
			}
			if _, ok := t.payload.PrivateClaims[k]; ok {
				if t.settings.CheckConstraints(Swap_Private) {
					return ErrClaimOverwritten
				} // Overwrie allowed so remove it from private set
				delete(t.payload.PrivateClaims, k)
			}
			t.header.PublicClaims[k] = v
		}
		return nil
	}
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
