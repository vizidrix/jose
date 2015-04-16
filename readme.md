
## JSON Object Signing and Encryption (JOSE)

The goal of this implementation is to:
- Provide a clean api for interacting with JOSE tokens
- Follow the existing standard as closely as possible
	- [JWS Spec](https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41)
	- [JWT Spec](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html)
- Include header information in signature
	- Avoid [Critical Security Vulnerabilities in JWT](https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/)

> Although many of the fields are strictly optional we recommend including unique and/or variable data in each token (i.e. at least one timestamp or a unique, random, nonce)

[Additional Security Guidelines](https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-10)

[Message Signature or MAC Computation](https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-5.1)

> Make an empty JWS with None and decode it
> { notice that explicitly enabling the algo is required in both encoding and decoding}

````
rem_none := j.RemoveConstraints(j.None_Algo)
jwt := j.New(rem_none)
_, err := j.Decode(jwt.GetToken(), rem_none)
````
