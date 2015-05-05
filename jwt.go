package jose

import (
	"bytes"
	"fmt"
)

// Header rovides members to describe the meta-data and protection for the payload and carry more visible processing data
// per spec: https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-4
type HeaderDef struct { // https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-4.1
	Type          string                 `json:"typ,omitempty"`    // MIME Media Type [IANA.MediaTypes] of this complete JWS
	ContentType   string                 `json:"cty,omitempty"`    // MIME Media Type [IANA.MediaTypes] of the secured content (the payload)
	Algorithm     string                 `json:"alg,omitempty"`    // The Signing / Encryption algorithm used on this token
	PublicParams  map[string]interface{} `json:"pub,omitempty"`    // Public header params should respect existing published params or be reasonably in control of the namespace
	PrivateParams map[string]interface{} `json:"pri,omitempty"`    // Private header params are unrestricted but should be understood by both producers and consumers
	PublicClaims  map[string]interface{} `json:"claims,omitempty"` // Map of keyed claims to include if provided, must be duplicated in and validated against matching claims in the payload
	JSONWebKey    WebKeySetDef           `json:"jwk,omitempty"`    // JWK encoded JSON web key rleated to this token
	JSONWebKeyUri string                 `json:"jku,omitempty"`    // Uri location of JWK encoded public key related to this token, must be TLS
	JSONWebKeyId  string                 `json:"kid,omitempty"`    // Value used to identify the key used to validating entity (when paired with Uri can identify item from set)

	// TODO: Implement checks for critical params
	//Critical      []string               `json:"crit,omitempty"`    // Indicates extensions to the spec that must be understood and respected if presented: https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-4.1.11

	// TODO: Implement certificate support features
	//X509Header string `json:"x5u,omitmepty"` // Uri location of the X.509 public key
	//X509CertChain []string `json:"x5c"` // Public key or cert chain of the cert used on the token: https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-4.1.6
	//X509SHA1 string `json:"x5t,omitempty"` // Base64 encoded DER encoding of an X.509 Certificate using SHA-1
	//X509SHA256 string `json:"x5t#S256"` // Base64 encoded DER encoding of an X.509 Certificate using SHA-256
}

// PayloadDef is used to describe the set of properties that can be encoded in the body of the token
// per spec: https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-08#section-1
type PayloadDef struct {
	Id             string                 `json:"jid,omitempty"`    // The UID for the JOSE payload to identify the data between parties
	ExpirationTime int64                  `json:"exp,omitempty"`    // UTC Unix time at which the token should no longer be excepted
	NotBefore      int64                  `json:"nbf,omitempty"`    // UTC Unix time before whtich the token should not be accepted for processing
	IssuedAtTime   int64                  `json:"iat,omitempty"`    // UTC Unix time at which the token was issued
	Issuer         string                 `json:"iss,omitempty"`    // The issuer of the claim or app which requested the token
	Audience       string                 `json:"aud,omitempty"`    // The aucience(s) of the token which can be used to identify intended recipients
	Tenant         string                 `json:"ten,omitempty"`    // The UID for the tenant of the issuing app
	Subject        string                 `json:"sub,omitempty"`    // The UID for the subject of the token which identifies the current user, if authenticated
	Principal      string                 `json:"prn,omitempty"`    // Legacy name of the property now called Subject
	Nonce          string                 `json:"non,omitempty"`    // A randomized nonce can be provided to ensure that hashes are not spoofable by replays for more static payloads
	Data           interface{}            `json:"dat,omitempty"`    // Custom payload data to include if provided
	PrivateClaims  map[string]interface{} `json:"claims,omitempty"` // Map of keyed claims to include if provided
}

func (h *HeaderDef) String() string {
	b := bytes.NewBufferString("\n{{ JWT Header:\n")

	write_prop(b, "Type", h.Type)
	write_prop(b, "Content Type", h.ContentType)
	write_prop(b, "Algorithm (*)", h.Algorithm)

	write_header(b, "Public Params", len(h.PublicParams))
	for k, v := range h.PublicParams {
		write_sub(b, k, v)
	}
	write_header(b, "Private Params", len(h.PrivateParams))
	for k, v := range h.PrivateParams {
		write_sub(b, k, v)
	}
	write_header(b, "Public Claims", len(h.PublicClaims))
	for k, v := range h.PublicClaims {
		write_sub(b, k, v)
	}
	write_prop(b, "KID", h.JSONWebKeyId)
	write_prop(b, "URI", h.JSONWebKeyUri)
	kl := len(h.JSONWebKey.Keys)
	write_prop(b, "JWK", fmt.Sprintf("[ %d ]", kl))
	if kl == 1 { // Use root header key def
		write_prop(b, "\tKey", fmt.Sprintf("%s", h.JSONWebKey))
	} else { // Use embedded key defs
		for i, k := range h.JSONWebKey.Keys {
			write_prop(b, fmt.Sprintf("\t[ %d ]", i), fmt.Sprintf("%s", k))
		}
	}
	write_json(b, "Header", h)
	b.WriteString("}}\n")
	return b.String()
}

func (p *PayloadDef) String() string {
	b := bytes.NewBufferString("\n{{ JWT Payload:\n")

	write_prop(b, "JID", p.Id)
	write_time(b, "Expires", p.ExpirationTime)
	write_time(b, "Not Before", p.NotBefore)
	write_time(b, "Issued At", p.IssuedAtTime)
	write_prop(b, "Issuer", p.Issuer)
	write_prop(b, "Audience", p.Audience)
	write_prop(b, "Tenant", p.Tenant)
	write_prop(b, "Subject", p.Subject)
	write_prop(b, "Principal", p.Principal)
	write_prop(b, "Nonce", p.Nonce)
	data := ""
	if p.Data != nil {
		data = fmt.Sprintf("%#v", p.Data)
	}
	write_prop(b, "Data", data)
	write_header(b, "Private Claims", len(p.PrivateClaims))
	for k, v := range p.PrivateClaims {
		write_sub(b, k, v)
	}
	write_json(b, "Payload", p)
	b.WriteString("}}\n")
	return b.String()
}
