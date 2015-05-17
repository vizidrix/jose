package jose_test

import (
	"fmt"
	. "github.com/stretchr/testify/assert"
	j "github.com/vizidrix/jose"
	"testing"
)

var rem_none = j.RemoveConstraints(j.CONST_None_Algo)

var secret = []byte("secret")

func Test__Set_key_use_correctly(t *testing.T) {
	ops := &j.WebKeyDef{}
	mod := j.Ops(j.Ops_Use_Sig)
	err := mod(ops)
	if NoError(t, err, "Set key ops sig %s", ops) &&
		Equal(t, "sig", ops.PublicKeyUse) {
		mod = j.Ops(j.Ops_Use_Enc)
		if NoError(t, mod(ops), "set key ops enc") &&
			Equal(t, "enc", ops.PublicKeyUse) {
			return
		}
	}
}

var key_ops_tests = []struct {
	flag j.JWKKeyOpFlag
	keys []string
}{ // TODO: Add these back as implemented
	{j.Ops_Sign, []string{"sign"}},
	{j.Ops_Verify, []string{"verify"}},
	//{j.Ops_Encrypt, []string{"encrypt"}},
	//{j.Ops_Decrypt, []string{"decrypt"}},
	//{j.Ops_WrapKey, []string{"wrapKey"}},
	//{j.Ops_UnwrapKey, []string{"unwrapKey"}},
	//{j.Ops_DeriveKey, []string{"deriveKey"}},
	//{j.Ops_DeriveBits, []string{"deriveBits"}},
	{j.Ops_Combo_SignVerify, []string{"sign", "verify"}},
	//{j.OpsCombo_EncryptDecrypt, []string{"encrypt", "decrypt"}},
	//{j.OpsCombo_WrapKeyUnwrapKey, []string{"wrapKey", "unwrapKey"}},
}

var not_implemented_key_ops = []j.JWKKeyOpFlag{
	j.Ops_Encrypt,
	j.Ops_Decrypt,
	j.Ops_WrapKey,
	j.Ops_UnwrapKey,
	j.Ops_DeriveKey,
	j.Ops_DeriveBits,
	//j.OpsCombo_EncryptDecrypt,
	//j.OpsCombo_WrapKeyUnwrapKey,
}

func Test__Correctly_set_valid_key_ops(t *testing.T) {
	for i, test := range key_ops_tests {
		ops := &j.WebKeyDef{}
		if !NoError(t, j.Ops(test.flag)(ops), "set key ops [ %d ]", i) {
			return
		}
		for i, k := range test.keys {
			for _, op := range ops.KeyOperations {
				if k == op {
					goto NEXT
				}
			}
			Fail(t, "Expected key @ [ %b ] == [ %s ] but found set [ %s ]", i, k, ops.KeyOperations)
			break
		NEXT:
		}
	}
}

func Test__Fail_unsupported_key_ops(t *testing.T) {
	for i, op := range not_implemented_key_ops {
		ops := &j.WebKeyDef{}
		EqualError(t, j.Ops(op)(ops), j.ErrNotImplemented.Error(), "%d", i)
	}
}

var invalid_key_op_combos = []struct {
	initial j.JWKKeyOpFlag
	invalid j.JWKKeyOpFlag
}{
	{j.Ops_Sign, j.Ops_Encrypt},
	{j.Ops_Sign, j.Ops_Decrypt},
	{j.Ops_Sign, j.Ops_DeriveKey},
	{j.Ops_Sign, j.Ops_DeriveBits},
	{j.Ops_Verify, j.Ops_Encrypt},
	{j.Ops_Verify, j.Ops_Decrypt},
	{j.Ops_Verify, j.Ops_DeriveKey},
	{j.Ops_Verify, j.Ops_DeriveBits},
}

func Test__Fail_invalid_key_ops(t *testing.T) {
	t.Skip("No conflicting options implemented yet")
	for i, v := range invalid_key_op_combos {
		EqualError(t, j.Ops(v.initial|v.invalid)(&j.WebKeyDef{}), j.ErrInvalidKeyOps.Error(), "check invalid ops [ %d ]", i)
	}
}

func Test__Fail_invalid_key_ops_cumulative(t *testing.T) {
	t.Skip("No conflicting options implemented yet")
	for i, v := range invalid_key_op_combos {
		ops := &j.WebKeyDef{} // Start with valid set
		if !NoError(t, j.Ops(v.initial)(ops), "setup initial ops [ %d ]", i) {
			return
		} // Try to append invalid component
		EqualError(t, j.Ops(v.invalid)(ops), j.ErrInvalidKeyOps.Error(), "check invalid ops [ %d ]", i)
	}
}

func Test__Initialize_TokenDef_with_correct_error(t *testing.T) {
	jwt := j.NewEmptyToken()
	errs := jwt.GetErrors()
	if Len(t, errs, 1, "invalid number of errors [ %s ]", errs) &&
		EqualError(t, errs[0], j.ErrUnitializedToken.Error()) {
		return
	}
}

func Test__Return_error_when_decoding_with_unsupported_none_algo(t *testing.T) {
	jwt := j.New(rem_none)
	token, err := jwt.GetToken()
	if !NoError(t, err, "making sample jwt") {
		return
	}
	jwt_parsed, err := j.Decode(token)
	if Nil(t, jwt_parsed, "decode should have failed") &&
		EqualError(t, err, j.ErrInvalidAlgorithm.Error(), "decode step") {
	}
}

func Test__Decode_allowed_none_algo(t *testing.T) {
	jwt := j.New(rem_none)
	token, err := jwt.GetToken()
	if !NoError(t, err, "making sample none algo jwt") {
		return
	}
	_, err = j.Decode(token, rem_none)
	NoError(t, err, "decode token with none algo")
}

func Test__Build_and_parse_valid_token(t *testing.T) {
	jwt := j.New(
		j.UseConstraints(j.CONST_None_Algo),
		j.Id(fmt.Sprintf("%X", uint64(3000))),
	)
	if !Nil(t, jwt.GetErrors(), "build valid token") {
		return
	}
	token, err := jwt.GetToken()
	if !NoError(t, err, "making sample valid jwt") {
		return
	}
	jwt_parsed, err := j.Decode(token, rem_none)
	if NoError(t, err, "parsing jwt token") &&
		True(t, jwt.Equals(jwt_parsed), "expected [ %#v ] but was [ %#v ]", jwt, jwt_parsed) {
	}
}

// JWK Tests

func Test__JWK_ToStrings_dont_error(t *testing.T) {
	k := j.WebKeyDef{}
	k_s := k.String()
	NotEmpty(t, k_s)
	ks := j.NewWebKeySet(k, k)
	k_s = ks.String()
	NotEmpty(t, k_s)
}

// JWT Tests

func Test_JWT_ToStrings_dont_error(t *testing.T) {
	h := &j.HeaderDef{}
	h_s := h.String()
	NotEmpty(t, h_s)
	p := &j.PayloadDef{}
	p_s := p.String()
	NotEmpty(t, p_s)
}

// Utility function tests

func Test__Clone_payload(t *testing.T) {
	jwt := j.New(j.Id("10"))
	p := jwt.GetPayload()

	Equal(t, "10", p.Id, "Should have cloned data into new payload")
}

func Test__Clone_interface(t *testing.T) {
	type thing struct {
		value string
		other int
	}
	v_in := &thing{"asdf", 10}
	var v_out *thing
	j.CloneInterface(v_in, v_out)
}

func Test__Clone_map(t *testing.T) {
	m := make(map[string]interface{})
	m["key1"] = "value1"

	var m2 map[string]interface{}
	j.CloneMap(m, &m2)

	if !Equal(t, "value1", m["key1"], "Should have retained initial values") ||
		!Equal(t, "value1", m2["key1"], "Should have cloned values into new map") {
		return
	}
	m2["key1"] = "value2"
	if !Equal(t, "value1", m["key1"], "Should have retained initial values after update") ||
		!Equal(t, "value2", m2["key1"], "Should have modifeid values in new map") {
		return
	}
	m["key1"] = "value3"
	if !Equal(t, "value3", m["key1"], "Should have modifeid values in old map") ||
		!Equal(t, "value2", m2["key1"], "Should have retained initial values after update") {
	}
}

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
