package jose

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"github.com/vizidrix/crypto"
	"hash"
)

var (
	noop_signer = func(b []byte) ([]byte, error) {
		return []byte{}, nil
	}
	noop_verifier = func(b, mac []byte) bool {
		return true
	}
	noop_encryptor = func(b []byte) ([]byte, error) {
		return b, nil
	}
	noop_decryptor = func(b []byte) ([]byte, error) {
		return b, nil
	}
)

type Provider interface {
	Kid() string
	Uri() string
	Algorithm() string
}

type ProviderModifier func(*ProviderDef)

type ProviderDef struct {
	kid       string
	uri       string
	alg       string
	webkeydef WebKeyDef
	signer    TokenSignerFunc
	verifier  TokenVerifierFunc
	encryptor TokenEncryptorFunc
	decryptor TokenDecryptorFunc
}

func NewProvider(kid string, webkey WebKeyDef, mods ...ProviderModifier) ProviderDef {
	r := ProviderDef{
		kid:       kid,
		uri:       "",
		webkeydef: webkey,
		signer:    noop_signer,
		verifier:  noop_verifier,
		encryptor: noop_encryptor,
		decryptor: noop_decryptor,
	}
	for _, mod := range mods {
		mod(&r)
	}
	return r
}

func (p ProviderDef) Kid() string {
	return p.kid
}

func (p ProviderDef) Uri() string {
	return p.uri
}

func (p ProviderDef) Algorithm() string {
	return p.alg
}

func (p ProviderDef) Sign(b []byte) ([]byte, error) {
	return p.signer(b)
}

func (p ProviderDef) Verify(b, mac []byte) bool {
	return p.verifier(b, mac)
}

func (p ProviderDef) Encrypt(b []byte) ([]byte, error) {
	return p.encryptor(b)
}

func (p ProviderDef) Decrypt(b []byte) ([]byte, error) {
	return p.decryptor(b)
}

func (p ProviderDef) Signer() TokenModifier {
	return &TokenModifierDef{
		name: "Provider Signer",
		modifier: func(t *TokenDef) error {
			if p.Kid() == "" {
				return ErrInvalidKey
			}
			for _, k := range t.GetWebKeys() {
				t := OpsMap[Ops_Sign]
				for _, op := range k.GetKeyOperations() {
					if op == t {
						return ErrDuplicateSigningKey
					}
				}
				//if !CheckOps(Ops_Sign, k.GetKeyOperations()...) {
				//	return ErrDuplicateSigningKey
				//}
			}
			t.signer = p
			t.verifier = p
			t.header.JSONWebKey = NewWebKeySet(p.webkeydef)
			t.header.Algorithm = p.Algorithm()
			t.header.JSONWebKeyId = p.Kid()
			t.header.JSONWebKeyUri = p.Uri()
			return nil
		},
	}
}

func Uri(uri string) ProviderModifier {
	return func(p *ProviderDef) {
		p.uri = uri
	}
}

func Algorithm(alg string) ProviderModifier {
	return func(p *ProviderDef) {
		p.alg = alg
	}
}

func Signer(f TokenSignerFunc) ProviderModifier {
	return func(p *ProviderDef) {
		p.signer = f
	}
}

func Verifier(f TokenVerifierFunc) ProviderModifier {
	return func(p *ProviderDef) {
		p.verifier = f
	}
}

func Encryptor(f TokenEncryptorFunc) ProviderModifier {
	return func(p *ProviderDef) {
		p.encryptor = f
	}
}

func Decryptor(f TokenDecryptorFunc) ProviderModifier {
	return func(p *ProviderDef) {
		p.decryptor = f
	}
}

type MacProviderDef struct {
	ProviderDef
	secret []byte
}

type HMACDef struct {
	name      string
	algorithm string
	hasher    func() hash.Hash
}

func HMAC(kid string, secret []byte, def *HMACDef, mods ...ProviderModifier) MacProviderDef {
	s := Signer(func(d []byte) (r []byte, err error) {
		buf := &bytes.Buffer{}
		s_mac := crypto.HMAC_Signer(sha256.New, secret)
		r, err = s_mac(d)
		enc := base64.NewEncoder(base64.URLEncoding, buf)
		enc.Write(r)
		enc.Close()
		r = bytes.TrimRight(buf.Bytes(), "=")
		return
	})
	v := Verifier(func(d, mac []byte) bool {
		v_mac := crypto.HMAC_Verifier(sha256.New, secret)
		return v_mac(d, mac)
	})
	return MacProviderDef{
		ProviderDef: NewProvider(kid, WebKeyDef{
			KeyType:       "oct",
			KeyOperations: GetOps(Ops_Combo_SignVerify),
			Algorithm:     def.algorithm,
			KeyId:         kid,
		}, append(mods, Algorithm(def.algorithm), s, v)...),
		secret: secret,
	}
}

func HS256(kid string, secret []byte, mods ...ProviderModifier) MacProviderDef {
	return HMAC(kid, secret, &HMACDef{"HMAC+SHA256", "HS256", sha256.New}, mods...)
}

func HS512(kid string, secret []byte, mods ...ProviderModifier) MacProviderDef {
	return HMAC(kid, secret, &HMACDef{"HMAC+SHA512", "HS512", sha512.New}, mods...)
}
