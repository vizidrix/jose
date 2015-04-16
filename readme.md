
## JSON Object Signing and Encryption 2 (JOSE2)

The goal of this implementation is to:
- Provide a clean api for interacting with JOSE tokens
- Follow the existing standard as closely as possible
	- [JWS Spec](https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41)
	- [JWT Spec](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html)
- Include header information in signature
	- Avoid [Critical Security Vulnerabilities in JWT](https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/))

> Although many of the fields are strictly optional we recommend including unique and/or variable data in each token (i.e. at least one timestamp or a unique, random, nonce)

[Additional Security Guidelines](https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-10)

[Message Signature or MAC Computation](https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-5.1)

````
var jose_token = "TOKEN_DATA.HEADER_DATA.PAYLOAD_DATA";
var encoded_sections = jose_token.split(".");
var verify_string = strings.Substring(jose_token, len(encoded_sections[0]));
var data_verified = jose.VerifyToken(encoded_sections[0], verify_string);
if !data_verified { Blow Up & Return }
...
````
