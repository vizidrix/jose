package jose

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"reflect"
)

func init() {
	log.SetFlags(log.Llongfile)
}

type TokenDef struct {
	settings *Settings
	header   *HeaderDef
	payload  *PayloadDef
	token    []byte
	errors   map[error]struct{}
}

var EmptyStruct = struct{}{}

func New(mods ...TokenModifier) *TokenDef {
	mods = append([]TokenModifier{Nonce(12)}, mods...)
	return NewEmptyToken().Mod(mods...)
}

func NewEmptyToken() *TokenDef {
	return &TokenDef{
		settings: &Settings{
			flags: Strict,
		},
		header: &HeaderDef{
			Type:          "JWT",
			ContentType:   "",
			Algorithm:     "none",
			PublicParams:  make(map[string]interface{}),
			PrivateParams: make(map[string]interface{}),
			PublicClaims:  make(map[string]interface{}),
		},
		payload: &PayloadDef{
			PrivateClaims: make(map[string]interface{}),
		},
		token: nil,
		errors: map[error]struct{}{
			ErrUnitializedToken: struct{}{},
		},
	}
}

func (t *TokenDef) Clone() *TokenDef {
	settings := *t.settings
	header := *t.header
	payload := *t.payload
	var token []byte
	if t.token != nil {
		copy(token, t.token)
	}
	return &TokenDef{
		settings: &settings,
		header:   &header,
		payload:  &payload,
		token:    token,
		errors:   nil,
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
	for _, mod := range mods {
		if err = mod(r); err != nil {
			r.AppendError(err)
		}
	}
	//log.Printf("\tMod.Token 1/2: [ %s ]\n\tw/ errors[%d] [ %#v ]", r.token, len(r.errors), r.errors)
	// ToDo: validations and append to t.errors
	if errs := r.GetErrors(); errs != nil {
		return r
	}
	if r.token, err = r.Encode(); err != nil {
		r.AppendError(err)
		return r
	}
	//log.Printf("Mod.Token 2/2: [ %s ]", r.token)
	return r
}

func (t *TokenDef) AppendKey(name, id string, e Encoder) {
	log.Printf("RegisterKey[ %s ] = [ %s ]", id, name)
	// Generate JWK
	// If no key set and keys is empty then just set value
	// If key is set and keys is empty then switch to keys and append
	// If keys is not empty then append to keys
}

func (t *TokenDef) Validate() (v_errs []error) {
	// ToDo: validations and append to v_errs on error

	return nil
}

func (t *TokenDef) Encode() (r []byte, err error) {
	return Encode(t)
}

func (t *TokenDef) GetToken() []byte {
	return t.token
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

func (t *TokenDef) EncodeHeader(w io.Writer) (err error) {
	if t == nil || t.header == nil {
		err = ErrRequiredElementWasNil
		return
	}
	var j []byte
	if j, err = json.Marshal(t.header); err == nil {
		enc := base64.NewEncoder(base64.URLEncoding, w)
		enc.Write(j)
		enc.Close()
	}
	return
}

func (t *TokenDef) GetHeader() (r HeaderDef, err error) {
	if t == nil || t.header == nil {
		err = ErrRequiredElementWasNil
		return
	}
	var i interface{}
	if i, err = CloneInterface(t.header); err == nil {
		r = i.(HeaderDef)
	}
	return
}

func (t *TokenDef) GetType() string {
	if t == nil || t.header == nil {
		panic(ErrRequiredElementWasNil)
	}
	return t.header.Type
}

func (t *TokenDef) GetAlgorithm() string {
	if t == nil || t.header == nil {
		panic(ErrRequiredElementWasNil)
	}
	return t.header.Algorithm
}

func (t *TokenDef) GetPublicParams() (r map[string]interface{}, err error) {
	if t == nil || t.header == nil {
		err = ErrRequiredElementWasNil
		return
	}
	r, err = CloneMap(t.header.PublicParams)
	return
}

func (t *TokenDef) GetPrivateParams() (r map[string]interface{}, err error) {
	if t == nil || t.header == nil {
		return nil, ErrRequiredElementWasNil
	}
	r, err = CloneMap(t.header.PrivateParams)
	return
}

func (t *TokenDef) GetPublicClaims() (r map[string]interface{}, err error) {
	if t == nil || t.header == nil {
		return nil, ErrRequiredElementWasNil
	}
	r, err = CloneMap(t.header.PublicClaims)
	return
}

func (t *TokenDef) GetWebKeys() (k []WebKeyReader, err error) {
	if t == nil || t.header == nil {
		return nil, ErrRequiredElementWasNil
	}
	panic("TODO") // Return single element or slice depending on setup / len of Keys
	return
}

func (t *TokenDef) EncodePayload(w io.Writer) (err error) {
	if t == nil || t.payload == nil {
		err = ErrRequiredElementWasNil
		return
	}
	var j []byte
	if j, err = json.Marshal(t.payload); err == nil {
		enc := base64.NewEncoder(base64.URLEncoding, w)
		enc.Write(j)
		enc.Close()
	}
	return
}

func (t *TokenDef) GetPayload() (r PayloadDef, err error) {
	if t == nil || t.payload == nil {
		err = ErrRequiredElementWasNil
		return
	}
	var i interface{}
	if i, err = CloneInterface(t.payload); err == nil {
		r = i.(PayloadDef)
	}
	return
}

func (t *TokenDef) GetId() string {
	if t == nil || t.payload == nil {
		panic(ErrRequiredElementWasNil)
	}
	return t.payload.Id
}

func (t *TokenDef) GetExpirationTime() int64 {
	if t == nil || t.payload == nil {
		panic(ErrRequiredElementWasNil)
	}
	return t.payload.ExpirationTime
}

func (t *TokenDef) GetNotBefore() int64 {
	if t == nil || t.payload == nil {
		panic(ErrRequiredElementWasNil)
	}
	return t.payload.NotBefore
}

func (t *TokenDef) GetIssuedAtTime() int64 {
	if t == nil || t.payload == nil {
		panic(ErrRequiredElementWasNil)
	}
	return t.payload.IssuedAtTime
}

func (t *TokenDef) GetIssuer() string {
	if t == nil || t.payload == nil {
		panic(ErrRequiredElementWasNil)
	}
	return t.payload.Issuer
}

func (t *TokenDef) GetAudience() string {
	if t == nil || t.payload == nil {
		panic(ErrRequiredElementWasNil)
	}
	return t.payload.Audience
}

func (t *TokenDef) GetTenant() string {
	if t == nil || t.payload == nil {
		panic(ErrRequiredElementWasNil)
	}
	return t.payload.Tenant
}

func (t *TokenDef) GetSubject() string {
	if t == nil || t.payload == nil {
		panic(ErrRequiredElementWasNil)
	}
	return t.payload.Subject
}

func (t *TokenDef) GetPrincipal() string {
	if t == nil || t.payload == nil {
		panic(ErrRequiredElementWasNil)
	}
	return t.payload.Principal
}

func (t *TokenDef) GetNonce() string {
	if t == nil || t.payload == nil {
		panic(ErrRequiredElementWasNil)
	}
	return t.payload.Nonce
}

func (t *TokenDef) GetData() (r interface{}, err error) {
	if t == nil || t.payload == nil {
		err = ErrRequiredElementWasNil
		return
	}
	r, err = CloneInterface(t.payload.Data)
	return
}

func (t *TokenDef) GetPrivateClaims() (r map[string]interface{}, err error) {
	if t == nil || t.payload == nil || t.header == nil {
		return nil, ErrRequiredElementWasNil
	}
	if r, err = CloneMap(t.payload.PrivateClaims); err != nil {
		return nil, err
	}
	for k, v := range t.header.PublicClaims {
		r[k] = v
	}
	return r, nil
}
