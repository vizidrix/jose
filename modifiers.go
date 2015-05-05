package jose

import (
	"github.com/vizidrix/crypto"
)

// TokenModifier is the signature of the function which can be used to modify a TokenDef
type TokenModifierFunc func(*TokenDef) error

type TokenModifier interface {
	Name() string
	Modifier(t *TokenDef) error
}

type TokenModifierDef struct {
	name     string
	modifier TokenModifierFunc
}

func (t *TokenModifierDef) Name() string {
	return t.name
}

func (t *TokenModifierDef) Modifier(d *TokenDef) error {
	return t.modifier(d)
}

var not_implemented = []JWKKeyOpFlag{
	Ops_Encrypt,
	Ops_Decrypt,
	Ops_WrapKey,
	Ops_UnwrapKey,
	Ops_DeriveKey,
	Ops_DeriveBits,
}

func Ops(ops JWKKeyOpFlag) KeyModifier {
	return func(t *WebKeyDef) error {
		if !CheckOps(ops, Ops_NoCheck) {
			for _, v := range not_implemented {
				if ops&v == v {
					return ErrNotImplemented
				}
			} // TODO: Enforce remaining checks per spec
			if ops&Ops_Cat_Sign > 0 && ops&Ops_Cat_Encrypt > 0 {
				return ErrInvalidKeyOps // Cannot cross functions on a key
			}
		} // Checks passed, set options
		t.PublicKeyUse = ""
		t.KeyOperations = make([]string, 0, 1)
		if CheckOps(ops, Ops_Use_Sig) {
			t.PublicKeyUse = "sig"
		}
		if CheckOps(ops, Ops_Use_Enc) {
			t.PublicKeyUse = "enc"
		}
		for k, v := range OpsMap {
			if ops&k == k {
				t.KeyOperations = append(t.KeyOperations, v)
			}
		}
		return nil
	}
}

func UseConstraints(cs ...ConstraintFlags) TokenModifier {
	return &TokenModifierDef{
		name: "UseConstraints",
		modifier: func(t *TokenDef) error {
			t.settings.UseConstraints(cs...)
			return nil
		},
	}
}
func RemoveConstraints(cs ...ConstraintFlags) TokenModifier {
	return &TokenModifierDef{
		name: "RemoveConstraints",
		modifier: func(t *TokenDef) error {
			t.settings.RemoveConstraints(cs...)
			return nil
		},
	}
}

func AddConstraints(cs ...ConstraintFlags) TokenModifier {
	return &TokenModifierDef{
		name: "AddConstraints",
		modifier: func(t *TokenDef) error {
			t.settings.AddConstraints(cs...)
			return nil
		},
	}
}

func Id(id string) TokenModifier {
	return &TokenModifierDef{
		name: "Id",
		modifier: func(t *TokenDef) error {
			t.payload.Id = id
			return nil
		},
	}
}

func Nonce(c int) TokenModifier {
	return &TokenModifierDef{
		name: "Nonce",
		modifier: func(t *TokenDef) error {
			if c < 0 {
				c = 0
			}
			t.payload.Nonce, _ = crypto.RandomString(c)
			return nil
		},
	}
}

func DisableNonce() TokenModifier {
	return &TokenModifierDef{
		name: "DisableNonce",
		modifier: func(t *TokenDef) error {
			t.payload.Nonce = ""
			return nil
		},
	}
}

func PrivateClaims(private map[string]interface{}) TokenModifier {
	return &TokenModifierDef{
		name: "PrivateClaims",
		modifier: func(t *TokenDef) error {
			for k, v := range private {
				if t.settings.CheckConstraints(CONST_Overwrite_Private) {
					if _, ok := t.payload.PrivateClaims[k]; ok {
						return ErrClaimOverwritten
					}
				}
				if _, ok := t.header.PublicClaims[k]; ok {
					if t.settings.CheckConstraints(CONST_Swap_Public) {
						return ErrClaimOverwritten
					} // Overwrie allowed so remove it from public set
					delete(t.header.PublicClaims, k)
				}
				t.payload.PrivateClaims[k] = v
			}
			return nil
		},
	}
}

func PublicClaims(public map[string]interface{}) TokenModifier {
	return &TokenModifierDef{
		name: "PublicClaims",
		modifier: func(t *TokenDef) error {
			for k, v := range public {
				if t.settings.CheckConstraints(CONST_Overwrite_Public) {
					if _, ok := t.header.PublicClaims[k]; ok {
						return ErrClaimOverwritten
					}
				}
				if _, ok := t.payload.PrivateClaims[k]; ok {
					if t.settings.CheckConstraints(CONST_Swap_Private) {
						return ErrClaimOverwritten
					} // Overwrie allowed so remove it from private set
					delete(t.payload.PrivateClaims, k)
				}
				t.header.PublicClaims[k] = v
			}
			return nil
		},
	}
}
