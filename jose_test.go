package jose_test

import (
	"fmt"
	j "github.com/vizidrix/crypto/jose"
	"log"
	"testing"
	//"time"
)

func AssertClaims(t *testing.T, expected, actual map[string]interface{}) {
	if len(expected) != len(actual) {
		t.Errorf("Invalid set of private claims returned expected [\n%#v\n] but was [\n%#v\n]", expected, actual)
		return
	}
	for ek, ev := range expected {
		if av, ok := actual[ek]; !ok {
			t.Errorf("Expected key [ %s ] but not found in [\n%#v\n]", ek, actual)
		} else {
			if ev != av {
				t.Errorf("Expected key [ %s ] with value [\n%#v\n] but was [\n%#v\n]", ek, ev, av)
			}
		}
	}
}

func ExpectError(t *testing.T, expected error, err error) bool {
	if err != expected {
		t.Errorf("Expected error [ %s ] but was [ %s ]", expected, err)
		return false
	}
	return true
}

func ExpectErrors(t *testing.T, errs []error, expected ...error) bool {
	return false
}

func ExpectNilError(t *testing.T, message string, err error) bool {
	if err != nil {
		t.Errorf("Unexpected error [ %s ] - Err: [ %s ]", message, err)
		return false
	}
	return true
}

func ExpectNilErrors(t *testing.T, message string, errs []error) bool {
	if errs != nil && len(errs) > 0 {
		t.Errorf("Unexpected errors [ %s ] - Err[%d]: [ %s ]", message, len(errs), errs)
		return false
	}
	return true
}

var rem_none = j.RemoveConstraints(j.None_Algo)

var secret = []byte("secret")

//func Test_Should_bypass_key_ops_checks_if_set(t *testing.T) {
//	t.Errorf("Not implemented yet")
//}

func Test_Should_set_key_use_correctly(t *testing.T) {
	ops := &j.WebKeyDef{}
	mod := j.Ops(j.Ops_Use_Sig)
	if err := mod(ops); !ExpectNilError(t, "Set Key Ops Sig", err) {
		return
	}
	if ops.PublicKeyUse != "sig" {
		t.Errorf("Expected [ sig ] but was [ %s ]", ops.PublicKeyUse)
	}
	mod = j.Ops(j.Ops_Use_Enc)
	if err := mod(ops); !ExpectNilError(t, "Set Key Ops Enc", err) {
		return
	}
	if ops.PublicKeyUse != "enc" {
		t.Errorf("Expected [ enc ] but was [ %s ]", ops.PublicKeyUse)
	}
}

func Test_Should_correctly_set_valid_key_ops(t *testing.T) {
	var ops *j.WebKeyDef
	test := func(op j.JWKKeyOps, keys []string) {
		ops = &j.WebKeyDef{}
		if err := j.Ops(op)(ops); !ExpectNilError(t, "Set Key Ops", err) {
			t.Errorf("Expected no error setting ops key [ %X ]", uint64(op))
		}
		for i, k := range keys {
			found := false
			for _, op := range ops.KeyOperations {
				if k == op {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected key @ [ %d | %b ] == [ %s ] but found set [ %s ]", i, uint64(op), k, ops.KeyOperations)
			}
		}
	}
	test(j.Ops_Sign, []string{"sign"})
	test(j.Ops_Verify, []string{"verify"})
	// TODO: Add these back as implemented
	//test(j.Ops_Encrypt, []string{"encrypt"})
	//test(j.Ops_Decrypt, []string{"decrypt"})
	//test(j.Ops_WrapKey, []string{"wrapKey"})
	//test(j.Ops_UnwrapKey, []string{"unwrapKey"})
	//test(j.Ops_DeriveKey, []string{"deriveKey"})
	//test(j.Ops_DeriveBits, []string{"deriveBits"})

	test(j.OpsCombo_SignVerify, []string{"sign", "verify"})
	//test(j.OpsCombo_EncryptDecrypt, []string{"encrypt", "decrypt"})
	//test(j.OpsCombo_WrapKeyUnwrapKey, []string{"wrapKey", "unwrapKey"})
}

func Test_Should_fail_unsupported_key_ops(t *testing.T) {
	var ops *j.WebKeyDef
	test := func(op j.JWKKeyOps) {
		ops = &j.WebKeyDef{}
		if err := j.Ops(op)(ops); !ExpectError(t, j.ErrNotImplemented, err) {
			return
		}
	} // Shouldn't allow use of placeholder features
	test(j.Ops_Encrypt)
	test(j.Ops_Decrypt)
	test(j.Ops_WrapKey)
	test(j.Ops_UnwrapKey)
	test(j.Ops_DeriveKey)
	test(j.Ops_DeriveBits)
}

func Test_Should_fail_invalid_key_ops(t *testing.T) {
	var ops *j.WebKeyDef
	test := func(op j.JWKKeyOps) {
		ops = &j.WebKeyDef{}
		if err := j.Ops(op)(ops); !ExpectError(t, j.ErrInvalidKeyOps, err) {
			return
		}
	} // Shouldn't allow mixing of ops with different purposes
	l := []j.JWKKeyOps{j.Ops_Sign, j.Ops_Verify}
	r := []j.JWKKeyOps{} // TODO: Check these as features are implemented
	//r := []j.JWKKeyOps{j.Ops_Encrypt, j.Ops_Decrypt, j.Ops_WrapKey, j.Ops_UnwrapKey}
	for _, lv := range l {
		for _, rv := range r {
			test(lv | rv)
		}
	}
}

/*
func Test_Should_not_validate_empty_token(t *testing.T) {
	token_def, err := j.NewJWT(j.HMAC256(secret), j.Strict)
	if ExpectNilError(t, "Make empty token", err) {
		return
	}
	token, err := token_def.GetToken()
	if ExpectNilError(t, "Get empty token", err) {
		return
	}
	valid, err := j.Validate(j.TenMinutes, token)

	if valid {
		t.Errorf("Validated empty token [ %#v ]", token)
	} else {
		ExpectError(t, j.ErrEmptyToken, err)
	}
}
*/

// j.HMAC256(secret)

func Test_Should_initialize_TokenDef_with_correct_error(t *testing.T) {
	jwt := j.NewEmptyToken()
	errs := jwt.GetErrors()
	l := len(errs)
	if l != 1 {
		t.Errorf("Invalid number of errors [ %d ] on new TokenDef [ %s ]", l, errs)
		return
	}
	if errs[0] != j.ErrUnitializedToken {
		t.Errorf("Incorrect initial error state for new TokenDef [ %s ]", errs[0])
	}
}

func Test_Should_return_error_when_decoding_with_unsupported_none_algo(t *testing.T) {
	jwt := j.New(rem_none)
	jwt_parsed, err := j.Decode(jwt.GetToken())
	if !ExpectError(t, j.ErrInvalidAlgorithm, err) {
		return
	}
	if !ExpectErrors(t, jwt_parsed.GetErrors(), j.ErrInvalidAlgorithm) {
		return
	}
}

func Test_Should_decode_allowed_none_algo(t *testing.T) {
	jwt := j.New(rem_none)
	_, err := j.Decode(jwt.GetToken(), rem_none)
	if !ExpectNilError(t, "Decode token with none algo", err) {
		return
	}
}

func Test_Should_build_and_parse_valid_token(t *testing.T) {
	jwt := j.New(
		j.UseConstraints(j.None_Algo),
		j.Id(fmt.Sprintf("%X", uint64(3000))),
	)
	if !ExpectNilErrors(t, "Build valid token", jwt.GetErrors()) {
		return
	}
	log.Printf("\n\tToken: [ %s ]", jwt.GetToken())
	jwt_parsed, err := j.Decode(jwt.GetToken(), rem_none)
	if !ExpectNilError(t, "Parsing jwt token", err) {
		return
	}
	if !jwt.Equals(jwt_parsed) {
		t.Errorf("Expected [\n%#v\n] but was [\n%#v\n]", jwt, jwt_parsed)
		return
	}
}

func Test_Should_auto_assign_kid_by_index_if_unset(t *testing.T) {
	//jwk := j.HS256(secret)

	//if jwk.GetKeyId() != "" {
	//	t.Errorf("Expected empty kid but found [ %s ]", jwk.GetKeyId())
	//}
}

/*
func Test_Should_build_and_parse_HS256_token(t *testing.T) {
	//jwk := j.HS256("one", secret)
	jwk_hmac_enc := j.HS256(secret).Encryptor(j.Ops(j.Ops_Cat_Encrypt))
	//log.Printf("\njwk: [ %#v ]", jwk)
	jwt := j.New(jwk_hmac_enc.Kid("one"))
	if !ExpectNilErrors(t, "Build valid token", jwt.GetErrors()) {
		return
	}
	jwt_parsed, err := j.Decode(jwt.GetToken(), jwk)
	if !ExpectNilError(t, "Parsing jwt token", err) {
		return
	}
	if !jwt.Equals(jwt_parsed) {
		t.Errorf("Expected [\n%#v\n] but was [\n%#v\n]", jwt, jwt_parsed)
		return
	}
}
*/

/* TODO: Other properties to validate:
j.IssuedAt(time.Now()+(10*time.Second)),
j.RedeemAt(time.Now()+(10*time.Minute)),
j.ExpireAt(time.Noew()+(60*time.Minute)),

j.IssueAfter(10*time.Second),
j.RedeemAfter(10*time.Minute),
j.ExpireAfter(60*time.Minute),

j.Issuer("myapp"),
j.Recipient("target_aud", "tenant", nil),
j.RandomNonce(),
j.Data(struct {
	SomeValue string
}{
	SomeValue: "value data",
}),
j.PublicParams(map[string]interface{}{
	"crit": []string{"xze"},
}),
j.PrivateParams(map[string]interface{}{
	"xze": "1.0.0",
}),
*/

// Claims Management

func Test_Should_append_private_claims(t *testing.T) {
	expected := map[string]interface{}{
		"a": "a-1",
		"b": "b-1",
	}

	jwt := j.New(rem_none,
		j.PrivateClaims(expected))
	if !ExpectNilErrors(t, "Append private claiims", jwt.GetErrors()) {
		return
	}
	priv_c, err := jwt.GetPrivateClaims()
	if !ExpectNilError(t, "Get private claims", err) {
		return
	}

	AssertClaims(t, expected, priv_c)
}

func Test_Should_append_public_claims_to_both_private_and_public(t *testing.T) {
	expected := map[string]interface{}{
		"a": "a-1",
		"b": "b-1",
	}

	jwt := j.New(rem_none,
		j.PublicClaims(expected))
	if !ExpectNilErrors(t, "Append public claims", jwt.GetErrors()) {
		return
	}
	pub_c, err := jwt.GetPublicClaims()
	if !ExpectNilError(t, "Get public claims", err) {
		return
	}
	priv_c, err := jwt.GetPrivateClaims()
	if !ExpectNilError(t, "Get private claims", err) {
		return
	}

	AssertClaims(t, expected, priv_c)
	AssertClaims(t, expected, pub_c)
}

func Test_Should_return_error_when_overwriting_private_claims_on_set(t *testing.T) {
	initial := map[string]interface{}{
		"a": "a-1",
		"b": "b-1",
	}
	overwrite := map[string]interface{}{
		"b": "b-2",
		"c": "c-2",
	}

	jwt := j.New(rem_none,
		j.PrivateClaims(initial),
		j.PrivateClaims(overwrite))
	if !ExpectErrors(t, jwt.GetErrors(), j.ErrClaimOverwritten) {
		return
	}
}

func Test_Should_return_error_when_overwriting_public_claims_on_set(t *testing.T) {
	initial := map[string]interface{}{
		"a": "a-1",
		"b": "b-1",
	}
	overwrite := map[string]interface{}{
		"b": "b-2",
		"c": "c-2",
	}

	jwt := j.New(rem_none,
		j.PublicClaims(initial),
		j.PublicClaims(overwrite))
	if !ExpectErrors(t, jwt.GetErrors(), j.ErrClaimOverwritten) {
		return
	}
}

func Test_Should_overwrite_found_claims_on_set_with_relaxed_options(t *testing.T) {
	initial := map[string]interface{}{
		"a": "a-1",
		"b": "b-1",
	}
	overwrite := map[string]interface{}{
		"b": "b-2",
		"c": "c-2",
	}
	expected := map[string]interface{}{
		"a": "a-1",
		"b": "b-2",
		"c": "c-2",
	}

	jwt := j.New(
		j.RemoveConstraints(j.Overwrite_Private),
		j.PrivateClaims(initial),
		j.PrivateClaims(overwrite))
	if !ExpectNilErrors(t, "Overwrite exsiting claims relaxed", jwt.GetErrors()) {
		return
	}
	priv_c, err := jwt.GetPrivateClaims()
	if !ExpectNilError(t, "Get private claims", err) {
		return
	}

	AssertClaims(t, expected, priv_c)
}

func Test_Should_swap_found_public_claims_on_set_with_relaxed_options(t *testing.T) {
	initial := map[string]interface{}{
		"a": "a-1",
		"b": "b-1",
	}
	overwrite := map[string]interface{}{
		"b": "b-2",
		"c": "c-2",
	}
	expected_priv := map[string]interface{}{
		"a": "a-1",
		"b": "b-2",
		"c": "c-2",
	}
	expected_pub := map[string]interface{}{
		"a": "a-1",
	}

	jwt := j.New(rem_none,
		j.RemoveConstraints(j.Swap_Public),
		j.PublicClaims(initial),
		j.PrivateClaims(overwrite))
	if !ExpectNilErrors(t, "swap exsiting public claims relaxed", jwt.GetErrors()) {
		return
	}
	priv_c, err := jwt.GetPrivateClaims()
	if !ExpectNilError(t, "Get private claims", err) {
		return
	}
	pub_c, err := jwt.GetPublicClaims()
	if !ExpectNilError(t, "Get public claims", err) {
		return
	}

	AssertClaims(t, expected_priv, priv_c)
	AssertClaims(t, expected_pub, pub_c)
}

func Test_Should_swap_found_private_claims_on_set_with_relaxed_options(t *testing.T) {
	initial := map[string]interface{}{
		"a": "a-1",
		"b": "b-1",
	}
	overwrite := map[string]interface{}{
		"b": "b-2",
		"c": "c-2",
	}
	expected_priv := map[string]interface{}{
		"a": "a-1",
		"b": "b-2",
		"c": "c-2",
	}
	expected_pub := map[string]interface{}{
		"b": "b-2",
		"c": "c-2",
	}

	jwt := j.New(rem_none,
		j.RemoveConstraints(j.Swap_Private),
		j.PrivateClaims(initial),
		j.PublicClaims(overwrite))
	if !ExpectNilErrors(t, "swap exsiting public claims relaxed", jwt.GetErrors()) {
		return
	}
	priv_c, err := jwt.GetPrivateClaims()
	if !ExpectNilError(t, "Get private claims", err) {
		return
	}
	pub_c, err := jwt.GetPublicClaims()
	if !ExpectNilError(t, "Get public claims", err) {
		return
	}

	AssertClaims(t, expected_priv, priv_c)
	AssertClaims(t, expected_pub, pub_c)
}

func Test_Should_merge_public_claims_into_private_set_for_SetClaims(t *testing.T) {
	initial_priv := map[string]interface{}{
		"a": "a-1",
		"b": "b-1",
	}
	expected_pub := map[string]interface{}{
		"c": "c-1",
		"d": "d-1",
	}
	expected_priv := map[string]interface{}{
		"a": "a-1",
		"b": "b-1",
		"c": "c-1",
		"d": "d-1",
	}

	jwt := j.New(rem_none,
		j.PrivateClaims(initial_priv),
		j.PublicClaims(expected_pub))
	if !ExpectNilErrors(t, "Merge public claims", jwt.GetErrors()) {
		return
	}
	priv_c, err := jwt.GetPrivateClaims()
	if !ExpectNilError(t, "Get private claims", err) {
		return
	}
	pub_c, err := jwt.GetPublicClaims()
	if !ExpectNilError(t, "Get public claims", err) {
		return
	}

	AssertClaims(t, expected_priv, priv_c)
	AssertClaims(t, expected_pub, pub_c)
}

func Test_Should_return_error_when_private_claims_are_set_public(t *testing.T) {
	claims := map[string]interface{}{
		"a": "a-1",
	}

	jwt := j.New(rem_none,
		j.PrivateClaims(claims),
		j.PublicClaims(claims))
	if !ExpectErrors(t, jwt.GetErrors(), j.ErrClaimOverwritten) {
		return
	}
}

func Test_Should_return_error_when_overwriting_public_claims_with_private(t *testing.T) {
	claims := map[string]interface{}{
		"a": "a-1",
	}

	jwt := j.New(rem_none,
		j.PublicClaims(claims),
		j.PrivateClaims(claims))
	if !ExpectErrors(t, jwt.GetErrors(), j.ErrClaimOverwritten) {
		return
	}
}
