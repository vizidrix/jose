package jose

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"reflect"
)

type TokenDef struct {
	settings  Settings
	header    HeaderDef
	payload   PayloadDef
	signer    TokenSigner
	verifier  TokenVerifier
	encryptor TokenEncryptor
	decryptor TokenDecryptor
	err_mods  map[int]string
	errors    map[error]struct{}
}

var EmptyStruct = struct{}{}

func New(mods ...TokenModifier) *TokenDef {
	mods = append([]TokenModifier{Nonce(12)}, mods...)
	return NewEmptyToken().Mod(mods...)
}

var NoneProvider = NewProvider("none", WebKeyDef{
	KeyType:       "none",
	KeyOperations: []string{},
	Algorithm:     "none",
	KeyId:         "none",
})

func NewEmptyToken() *TokenDef {
	return &TokenDef{
		settings: Settings{
			flags: CONST_Strict,
		},
		header: HeaderDef{
			PublicParams:  make(map[string]interface{}),
			PrivateParams: make(map[string]interface{}),
			PublicClaims:  make(map[string]interface{}),
		},
		payload: PayloadDef{
			PrivateClaims: make(map[string]interface{}),
		},
		signer:    NoneProvider,
		verifier:  NoneProvider,
		encryptor: NoneProvider,
		decryptor: NoneProvider,
		err_mods:  make(map[int]string),
		errors: map[error]struct{}{
			ErrUnitializedToken: struct{}{},
		},
	}
}

func (t *TokenDef) Clone() *TokenDef {
	return &TokenDef{
		settings:  t.settings,
		header:    t.GetHeader(),
		payload:   t.GetPayload(),
		signer:    t.signer,
		verifier:  t.verifier,
		encryptor: t.encryptor,
		decryptor: t.decryptor,
		err_mods:  make(map[int]string),
		errors:    nil,
	}
}

func (t *TokenDef) Equals(o *TokenDef) bool {
	h_ok := reflect.DeepEqual(t.header, o.header)
	p_ok := reflect.DeepEqual(t.payload, o.payload)
	return h_ok && p_ok
}

func (t *TokenDef) AppendError(err error) {
	if t.errors == nil {
		t.errors = make(map[error]struct{})
	}
	t.errors[err] = EmptyStruct
}

func (t *TokenDef) Mod(mods ...TokenModifier) (r *TokenDef) {
	var err error
	r = t.Clone()
	for i, mod := range mods {
		if err = mod.Modifier(r); err != nil {
			t.err_mods[i] = mod.Name()
			r.AppendError(err)
		}
	}
	// ToDo: validations and append to t.errors
	if errs := r.GetErrors(); errs != nil {
		return r
	}
	return r
}

func (t *TokenDef) Encrypt(buf []byte) ([]byte, error) {
	return t.encryptor.Encrypt(buf)
}

func (t *TokenDef) Decrypt(buf []byte) ([]byte, error) {
	return t.decryptor.Decrypt(buf)
}

func (t *TokenDef) Sign(buf []byte) ([]byte, error) {
	return t.signer.Sign(buf)
}

func (t *TokenDef) Verify(buf, mac []byte) bool {
	return t.verifier.Verify(buf, mac)
}
func (t *TokenDef) GetToken() ([]byte, error) {
	return Encode(t)
}

func encode(w io.Writer, v interface{}) (err error) {
	var j []byte
	if j, err = json.Marshal(v); err == nil {
		enc := base64.NewEncoder(base64.URLEncoding, w)
		enc.Write(j)
		enc.Close()
	}
	return
}

func (t *TokenDef) EncodeHeader(w io.Writer) (err error) {
	return encode(w, t.header)
}

func (t *TokenDef) EncodePayload(w io.Writer) (err error) {
	return encode(w, t.payload)
}

func (t *TokenDef) GetErrors() []error {
	if t == nil {
		return []error{ErrRequiredElementWasNil}
	}
	if t.errors == nil {
		return nil
	}
	l := len(t.errors)
	if l == 0 {
		return nil
	}
	i := 0
	errs := make([]error, l, l)
	for k, _ := range t.errors {
		errs[i] = k
		i++
	}
	return errs
}

func (t *TokenDef) GetHeader() (r HeaderDef) {
	r = t.header
	CloneMap(t.header.PublicParams, &r.PublicParams)
	CloneMap(t.header.PrivateParams, &r.PrivateParams)
	CloneMap(t.header.PublicClaims, &r.PublicClaims)
	return
}

func (t *TokenDef) GetType() string {
	return t.header.Type
}

func (t *TokenDef) GetAlgorithm() string {
	return t.header.Algorithm
}

func (t *TokenDef) GetPublicParams() (r map[string]interface{}) {
	r = make(map[string]interface{})
	CloneMap(t.header.PublicParams, &r)
	return
}

func (t *TokenDef) GetPrivateParams() (r map[string]interface{}) {
	r = make(map[string]interface{})
	CloneMap(t.header.PrivateParams, &r)
	return
}

func (t *TokenDef) GetPublicClaims() (r map[string]interface{}) {
	r = make(map[string]interface{})
	CloneMap(t.header.PublicClaims, &r)
	return
}

func (t *TokenDef) GetWebKeys() (k []WebKeyReader) {
	jwk := t.header.JSONWebKey
	l := len(jwk.Keys)
	if l == 0 { // If there are no child keys assume the root is the definitive
		return []WebKeyReader{jwk}
	}
	k = make([]WebKeyReader, l, l)
	for i := 0; i < l; i++ {
		k[i] = jwk.Keys[i]
	}
	//panic("TODO") // Return single element or slice depending on setup / len of Keys
	return
}

func (t *TokenDef) GetPayload() (r PayloadDef) {
	r = t.payload
	CloneMap(t.payload.PrivateClaims, &r.PrivateClaims)
	return
}

func (t *TokenDef) GetId() string {
	return t.payload.Id
}

func (t *TokenDef) GetExpirationTime() int64 {
	return t.payload.ExpirationTime
}

func (t *TokenDef) GetNotBefore() int64 {
	return t.payload.NotBefore
}

func (t *TokenDef) GetIssuedAtTime() int64 {
	return t.payload.IssuedAtTime
}

func (t *TokenDef) GetIssuer() string {
	return t.payload.Issuer
}

func (t *TokenDef) GetAudience() string {
	return t.payload.Audience
}

func (t *TokenDef) GetTenant() string {
	return t.payload.Tenant
}

func (t *TokenDef) GetSubject() string {
	return t.payload.Subject
}

func (t *TokenDef) GetPrincipal() string {
	return t.payload.Principal
}

func (t *TokenDef) GetNonce() string {
	return t.payload.Nonce
}

func (t *TokenDef) GetData(result interface{}) (err error) {
	if result == nil {
		return ErrProvidedDataWasNil
	}
	CloneInterface(t.payload.Data, result)
	return
}

func (t *TokenDef) GetPrivateClaims() (r map[string]interface{}) {
	r = make(map[string]interface{})
	CloneMap(t.payload.PrivateClaims, &r)
	for k, v := range t.header.PublicClaims {
		r[k] = v
	}
	return
}
