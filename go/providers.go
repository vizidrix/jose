package jose

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

func HS256(id string, secret []byte) TokenModifier {
	return func(t *TokenDef) error {
		e := HMAC_Encoder(sha256.New, secret)
		t.AppendKey("HS256", id, e)

		return nil
	}
}

func HS512(id string, secret []byte) TokenModifier {
	return func(t *TokenDef) error {
		e := HMAC_Encoder(sha512.New, secret)
		t.AppendKey("HS256", id, e)

		return nil
	}
}

type Encoder func([]byte) ([]byte, error)
type Checker func([]byte) error

func HMAC_Encoder(h func() hash.Hash, secret []byte) Encoder {
	return func(v []byte) (r []byte, err error) {
		mac := hmac.New(h, secret)
		_, err = mac.Write(v)
		if err != nil {
			return
		}
		copy(r, mac.Sum(nil))
		mac.Reset()
		return
	}
}
