package jose

import (
	"bytes"
	"github.com/vizidrix/crypto"
	//"log"
)

func Kid(id string) KeyModifier {
	return func(t *WebKeyDef) error {
		t.KeyId = id
		return nil
	}
}

var not_implemented = []JWKKeyOps{
	Ops_Encrypt,
	Ops_Decrypt,
	Ops_WrapKey,
	Ops_UnwrapKey,
	Ops_DeriveKey,
	Ops_DeriveBits,
}

func Ops(ops JWKKeyOps) KeyModifier {
	return func(t *WebKeyDef) error {
		if !CheckOps(ops, Ops_NoCheck) {
			for _, v := range not_implemented {
				if ops&v == v {
					return ErrNotImplemented
				}
			}
			// TODO: Enforce remaining checks per spec
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

func Load(token []byte) TokenModifier {
	return func(t *TokenDef) error {
		var err error
		segs := bytes.Split(token, period_slice)
		if len(segs) != 3 {
			return ErrDecodeInvalidToken
		}
		s_len := len(segs[2])
		if s_len == 0 { // None signature
			if t.settings.CheckConstraints(None_Algo) { // Require explicit acceptance
				return ErrInvalidAlgorithm
			}
		}
		h_len := len(segs[0])
		p_len := len(segs[1])
		if err = json_decode_trimmed_base64(h_len, segs[0], t.header); err != nil {
			return err
		}
		if err = json_decode_trimmed_base64(p_len, segs[1], t.payload); err != nil {
			return err
		}
		return nil
	}
}

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

func Nonce(c int) TokenModifier {
	return func(t *TokenDef) error {
		if t == nil || t.payload == nil {
			return ErrRequiredElementWasNil
		}
		if c < 0 {
			c = 0
		}
		t.payload.Nonce, _ = crypto.RandomString(c)
		return nil
	}
}

func DisableNonce() TokenModifier {
	return func(t *TokenDef) error {
		if t == nil || t.payload == nil {
			return ErrRequiredElementWasNil
		}
		t.payload.Nonce = ""
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
