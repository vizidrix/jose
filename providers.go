package jose

import (
//"crypto/sha256"
//"crypto/sha512"
//"hash"
//"io"
)

//type Encoder func(h io.Reader, p io.Writer)

func HS256(secret []byte) TokenModifier {
	//e := HMAC_Encoder(sha256.New, secret)
	return func(t *TokenDef) error {
		//t.AppendKey("HS256", e)
		//io.
		return nil
	}
}

func HS512(secret []byte) TokenModifier {
	//e := HMAC_Encoder(sha512.New, secret)
	return func(t *TokenDef) error {
		//t.AppendKey("HS256", id, e)
		return nil
	}
}
