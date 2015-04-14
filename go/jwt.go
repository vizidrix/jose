package jwt

import (
	"encoding/base64"
)

type JWTEncoder interface {
	Encode(interface{}) []byte
}

// JWT is a standard that describes a standaard formaat for encoding JSON Web Tokens
type jwt struct {
	secret []byte
}

func NewJWT(secret []byte) JWTEncoder {
	return &jwt{
		secret: secret,
	}
}

func (e *jwt) Encode(payload interface{}) []byte {

}
