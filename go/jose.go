// Package jose provides a suite of utilities to implement a variant of the JWT spec, see [https://github.com/vizidrix/jsoe/readme.md for more details
package jose

const ( // https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-4.1.9

)

type Header struct { // https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-4.1
	Algorithm     string `json:"alg,omitempty"` // The Signing / Encryption algorithm used on this token
	Type          string `json:"typ,omitempty"` // Type of token [ JWS (Signature) | JWT (Token) | JWE (Encryption) ]
	JSONWebKey    string `json:"jwk,omitempty"` // JWK encoded JSON web key rleated to this token
	JSONWebKeyUri string `json:"jku,omitempty"` // Uri location of JWK encoded public key related to this token, must be TLS
	JSONWebKeyId  string `json:"kid,omitempty"` // Value used to identify the key used to validating entity (when paired with Uri can identify item from set)
	//SHA1Thumbprint string `json:"x5t,omitempty"` // Base64 encoded DER encoding of an X.509 Certificate using SHA-1
	//SHA256Thumbprint string `json:"x5t#S256"` // Base64 encoded DER encoding of an X.509 Certificate using SHA-256
}

type Payload struct {
	Id             string `json:"jid,omitempty"`    // The UID for the JOSE
	ExpirationTime int64  `json:"exp,omitempty"`    // UTC Unix time at which the token should no longer be excepted
	NotBefore      int64  `json:"nbf,omitempty"`    // UTC Unix time before whtich the token should not be accepted for processing
	IssuedAtTime   int64  `json:"iat,omitempty"`    // UTC Unix time at which the token was issued
	Issuer         string `json:"iss,omitempty"`    // The issuer of the claim or app which requested the token
	Audience       string `json:"aud,omitempty"`    // The aucience(s) of the token which can be used to identify intended recipients
	Tenant         string `json:"tenant,omitempty"` // The UID for the tenant of the issuing app
	Principal      string `json:"prn,omitempty"`    // The UID for the subject of the token which identifies the current user, if authenticated

	Data   interface{}            `json:"data,omitempty"`   // Custom payload data to include if provided
	Claims map[string]interface{} `json:"claims,omitempty"` // Map of keyed claims to include if provided
}

// Option to set skew - variance allowed by clock time checks
// Option to provide time - to keep the library pure

// QueryStringHash string `json:"qsh"` // Hash producded from the Method, Relative Path plus the Sorted Set of Query String Params, used to prevent URL tampering
