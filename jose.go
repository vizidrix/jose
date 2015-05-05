// Package jose provides a suite of utilities to implement a variant of the JWT spec, see [https://github.com/vizidrix/jsoe/readme.md for more details
package jose

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	//"log"
)

var (
	ErrNotImplemented            = errors.New("not yet implemented")
	ErrClaimOverwritten          = errors.New("cannot overwrite a claim that was previously set")
	ErrInvalidFormat             = errors.New("unable to parse data structure")
	ErrEmptyToken                = errors.New("cannot validate an empty token")
	ErrInvalidAlgorithm          = errors.New("unable to use provided algorithm")
	ErrInvalidKey                = errors.New("unable to use provided key definition")
	ErrInvalidKeyOps             = errors.New("unable to use provided key operations")
	ErrDuplicateSigningKey       = errors.New("token already has defined signature key")
	ErrDuplicateEncryptingKey    = errors.New("token already has defined encryption key")
	ErrDecodeInvalidToken        = errors.New("cannot decode invalid token")
	ErrDecodeInvalidSignature    = errors.New("cannot decode invalid signature")
	ErrDecodeInvalidHeader       = errors.New("cannot decode invalid header")
	ErrDecodeInvalidPayload      = errors.New("cannot decode invalid payload")
	ErrSignatureValidationFailed = errors.New("signature validation failed")
	ErrUnitializedToken          = errors.New("uninitialized token cannot be used")
	ErrRequiredElementWasNil     = errors.New("required token def element was nil")
)

type ErrEncodeInvalidTokenDef struct {
	error
	errors []error
}

func ErrEncodeInvalidToken(errs []error) ErrEncodeInvalidTokenDef {
	b := bytes.NewBufferString("cannot encode invalid token")
	b.WriteString(fmt.Sprintf(" [ %d ]:\n", len(errs)))
	for i := 0; i < len(errs); i++ {
		b.WriteString(fmt.Sprintf("\t%s\n", errs[i]))
	}
	return ErrEncodeInvalidTokenDef{
		error:  errors.New(b.String()),
		errors: errs,
	}
}

const (
	period     = 46
	equals     = 61
	prop_fmt   = "\t%20s:\t%s\n"
	header_fmt = "\t%20s\n"
)

var period_slice = []byte{'.'}
var equals_slice = []byte{'='}

var base64_padding = map[int][]byte{
	0: []byte{},
	1: bytes.Repeat(equals_slice, 3),
	2: bytes.Repeat(equals_slice, 3),
	3: bytes.Repeat(equals_slice, 1),
}

type TokenSignerFunc func([]byte) ([]byte, error)
type TokenVerifierFunc func([]byte, []byte) bool
type TokenEncryptorFunc func([]byte) ([]byte, error)
type TokenDecryptorFunc func([]byte) ([]byte, error)

type TokenSigner interface {
	Sign([]byte) ([]byte, error)
}

type TokenVerifier interface {
	Verify([]byte, []byte) bool
}

type TokenEncryptor interface {
	Encrypt([]byte) ([]byte, error)
}

type TokenDecryptor interface {
	Decrypt([]byte) ([]byte, error)
}

// WebKeyReader provides access to read/only properties and methods of a web key definition
// Any reference data should be obfuscated to ensure against unintentional or invalid modification
type WebKeyReader interface {
	GetKeyType() string
	GetPubilcKeyUse() string
	GetKeyOperations() []string
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

// KeyModifier is the signature of a function which can be used to modifiy a WebKeyDef
type KeyModifier func(*WebKeyDef) error

var WebKeyDef_None = WebKeyDef{
	KeyType: "none",
	KeyId:   "none",
}

const ( // https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-4.1.9
	JOSE_JWT      = "JWT"
	JOSE_JWT_JSON = "JWT+JSON"
	//JOSE_JWE      = "JWE"
	//JOSE_JWE_JSON = "JWE+JSON"
	//JOSE_JWK      = "JWK"
	//JOSE_JWK_JSON = "JWK+JSON"
)

// ConstraintFlags alter the behavior of the token definition logic to provide configurable protection levels
type ConstraintFlags int64

const (
	CONST_None_Algo          ConstraintFlags                                    = 1 << iota // Blocks the validator from passing a "none" algo definition
	CONST_Alg_Only                                                                          // Block tokens that don't provide JWK entries for Keys (disable "alg" only by default, see security vulnerability in readme)
	CONST_Overwrite_Private                                                                 // Blocks private claims from being overwritten by other subsequent updates to the same key
	CONST_Overwrite_Public                                                                  // Blocks public claims from being overwritten by other subsequent updates to the same key
	CONST_Swap_Private                                                                      // Blocks silent upgrading of private claims to public claims, risks exposing or discarding data intended to be private
	CONST_Swap_Public                                                                       // Blocks silent downgrading of public claims to private claims, risks hiding data intended to be public
	CONST_Overwrites         = CONST_Overwrite_Private | CONST_Overwrite_Public             // Blocks both overwrite cases
	CONST_Swaps              = CONST_Swap_Private | CONST_Swap_Public                       // Blocks both swap cases
	CONST_OverwritesAndSwaps = CONST_Overwrites | CONST_Swaps                               // Blocks all claim related cases
	CONST_Strict             = CONST_None_Algo | CONST_OverwritesAndSwaps                   // Blocks all defined constraints, intended to provide the safest constraint option
	CONST_None               = 0                                                            // Disables all constraints
)

type Settings struct {
	flags ConstraintFlags
}

func (s *Settings) UseConstraints(cf ...ConstraintFlags) {
	s.flags = CONST_None
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

func Encode(t *TokenDef) ([]byte, error) {
	if t.errors != nil {
		errs := make([]error, 0, len(t.errors))
		for k, _ := range t.errors {
			errs = append(errs, k)
		}
		return nil, ErrEncodeInvalidToken(errs)
	}
	h_buf := &bytes.Buffer{}
	if err := t.EncodeHeader(h_buf); err != nil {
		return nil, err
	}
	h := bytes.TrimRight(h_buf.Bytes(), "=")
	p_buf := &bytes.Buffer{}
	if err := t.EncodePayload(p_buf); err != nil {
		return nil, err
	}
	p := bytes.TrimRight(p_buf.Bytes(), "=")
	d := &bytes.Buffer{}
	d.Write(h)
	d.WriteByte(period)
	if e, err := t.Encrypt(p); err != nil {
		return nil, err
	} else {
		d.Write(e)
	}
	if s, err := t.Sign(d.Bytes()); err != nil {
		return nil, err
	} else {
		//log.Printf("Signature [ %s ]", s)
		d.WriteByte(period)
		d.Write(s)
	}
	//log.Printf("\nEncode Token:\n[ %s + %s ] ==>\n\t%s\n",
	//	h, p, d.Bytes())

	return d.Bytes(), nil
}

// Decode parses, validates and extracts the state of the token, returning an error if any part fails
func Decode(token []byte, mods ...TokenModifier) (r *TokenDef, err error) {
	var l TokenModifier
	if l, err = Parse(token); err != nil {
		return
	}
	//mods = append(mods, load(token))
	mods = append(mods, l)
	//for i, mod := range mods {
	//log.Printf("Token Mod[ %d ]: [ %#v ]", i, mod)
	//}
	t := NewEmptyToken().Mod(mods...)
	errs := t.GetErrors()
	if errs != nil {
		if _, ok := t.errors[ErrInvalidAlgorithm]; ok {
			return nil, ErrInvalidAlgorithm
		}
		//log.Printf("Decode [\n%s\n]== [ %#v ]\n", errs, t.err_mods)
		return nil, ErrDecodeInvalidToken
	}
	return t, nil
}

func Parse(token []byte) (TokenModifier, error) {
	segs := bytes.Split(token, period_slice)
	if len(segs) != 3 {
		return nil, ErrDecodeInvalidToken
	}
	h_len := len(segs[0])
	p_len := len(segs[1])
	s_len := len(segs[2])
	return &TokenModifierDef{
		name: "Parse",
		modifier: func(t *TokenDef) (err error) {
			if s_len == 0 { // None signature
				if t.settings.CheckConstraints(CONST_None_Algo) { // Require explicit acceptance
					return ErrInvalidAlgorithm
				}
			} else { // Signature found, check it
				var s []byte
				p := token[:h_len+p_len+1] // Grab first two chunks and sign to validate signature

				if s, err = DecodeRawSegment(segs[2]); err != nil {
					//log.Printf("\nDecode signature error: [ %s ]", err)
					return ErrDecodeInvalidSignature
				}
				//log.Printf("Compare: p [ %s ] to s [ %s ]", p, s)
				if !t.Verify(p, s) {
					//log.Printf("Invalid signature")
					return ErrSignatureValidationFailed
					//panic("invalid signature")
				}
			} // Verify / Decrypt using configured key(s)

			/*
				if s, err = t.Sign(p); err != nil { // Generate signature for comparison
					return err
				}
				log.Printf("\n* Compare signatures:\n\nT:\t%s\n\nP:\t%s\n\nGen:\t%s\n\nFound:\t%s\n\n\n", token, p, s, segs[2])
				if string(s) != string(segs[2]) {
					panic("invalid signature") // TODO: return real error
				}
			*/
			if err := DecodeRawJsonSegment(h_len, segs[0], &t.header); err != nil {
				return ErrDecodeInvalidHeader
			}
			//log.Printf("Decoded header: [ %s ]", t.header)
			if err := DecodeRawJsonSegment(p_len, segs[1], &t.payload); err != nil {
				return ErrDecodeInvalidPayload
				// any other processing
			}
			//log.Printf("Decoded payload: [ %s ]", t.payload)
			return nil
		},
	}, nil
}

func WrapErr(message string, err error) error {
	return errors.New(fmt.Sprintf("%s: [ %s ]", message, err))
}

func CloneMap(in map[string]interface{}, out *map[string]interface{}) {
	r := make(map[string]interface{})
	for k, v := range in {
		r[k] = v
	}
	*out = r
}

func CloneInterface(in interface{}, out interface{}) {
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	var err error
	if err = enc.Encode(in); err == nil {
		dec := json.NewDecoder(buf)
		if err = dec.Decode(out); err == nil {
			return
		} else {
			if err = dec.Decode(&out); err == nil {
				return
			}
		}
	}
	panic(err)
}

func DecodeRawSegment(d []byte) (r []byte, err error) {
	l := len(d)
	m := l % 4
	b := bytes.NewBuffer(make([]byte, 0, l+m))
	b.Write(d)
	b.Write(base64_padding[m])
	//log.Printf("Base64 Decode: [ %s + %d ] == [ %s ]", d, m, b.String())
	r, err = base64.URLEncoding.DecodeString(b.String())
	return
}

func DecodeRawJsonSegment(l int, d []byte, t interface{}) (err error) {
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

func write_prop(b *bytes.Buffer, title, value string) {
	v := "[ N/A ]"
	if value != "" {
		if value == "-" {
			v = "-"
		} else {
			v = fmt.Sprintf("[ %s ]", value)
		}
	}
	b.WriteString(fmt.Sprintf(prop_fmt, title, v))
}

func write_header(b *bytes.Buffer, title string, count int) {
	write_prop(b, fmt.Sprintf("%s [ %d ]", title, count), "-")
}

func write_sub(b *bytes.Buffer, title string, value interface{}) {
	write_prop(b, title, fmt.Sprintf("%#v", value))
}

func write_time(b *bytes.Buffer, title string, time int64) {
	if time == 0 {
		write_prop(b, title, "")
		return
	}
	write_prop(b, title, fmt.Sprintf("%d -> %s", time, time))
}

func write_json(b *bytes.Buffer, title string, v interface{}) error {
	write_prop(b, title, "-")
	b.WriteString("\t==> ")
	e := json.NewEncoder(b)
	if err := e.Encode(v); err != nil {
		return err
	}
	b.WriteString("\n")
	return nil
}
