package jose_test

import (
	. "github.com/stretchr/testify/assert"
	j "github.com/vizidrix/jose"
	"testing"
)

func Test__Encode_and_decode_HMAC256_signed_token(t *testing.T) {
	secret := []byte("secret")
	key := j.HS256("a", secret).Signer()
	jwt := j.New(
		key,
		j.Id("10"),
	)
	token, err := jwt.GetToken()
	if !NoError(t, err, "should have built token") {
		return
	}
	h := jwt.GetHeader()
	Equal(t, "HS256", h.JSONWebKey.Algorithm, "Should have set signature algorithm")
	Equal(t, "HS256", h.JSONWebKey.Algorithm, "Should have set web key signature algorithm")

	if jwt_parsed, err := j.Decode(token, key); err != nil {
		NoError(t, err, "should not have failed decode")
	} else {
		Equal(t, "10", jwt_parsed.GetId(), "should have decoded valid id")
	}
}

/*
func Test_Should_build_and_parse_valid_provider_token(t *testing.T) {
	secret := []byte("secret")
	id := fmt.Sprintf("%X", uint64(10))
	s := j.NewKeyStore(map[string]func(){
		"kid1": j.HS256(secret),
	})
	//secret_config := j.HS256("kid", secret)
	//jwt := j.New(secret_config)
	jwt := j.New(
		s.SignWith("kid1"),
		j.Id(id),
	)
	if !ExpectNilErrors(t, "Build valid hmac token", jwt.GetErrors()) {
		return
	}
	token, _ := jwt.GetToken()
	log.Printf("\n\tToken: [ %s ]", token)
	jwt_parsed, err := j.Decode(token, s.Keys())
	if !ExpectNilError(t, "Parsed hmac jwt token", err) {
		return
	}
	if !jwt.Equals(jwt_parsed) {
		t.Errorf("Expected [\n%#v\n] but was [\n%#v\n]", jwt, jwt_parsed)
		return
	}
}
*/
