package jose_test

import (
	"fmt"
	j "github.com/vizidrix/jose"
	"testing"
)

var rem_none = j.RemoveConstraints(j.CONST_None_Algo)

var secret = []byte("secret")

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
	test := func(op j.JWKKeyOpFlag, keys []string) {
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

	test(j.Ops_Combo_SignVerify, []string{"sign", "verify"})
	//test(j.OpsCombo_EncryptDecrypt, []string{"encrypt", "decrypt"})
	//test(j.OpsCombo_WrapKeyUnwrapKey, []string{"wrapKey", "unwrapKey"})
}

func Test_Should_fail_unsupported_key_ops(t *testing.T) {
	var ops *j.WebKeyDef
	test := func(op j.JWKKeyOpFlag) {
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
	test := func(op j.JWKKeyOpFlag) {
		ops = &j.WebKeyDef{}
		if err := j.Ops(op)(ops); !ExpectError(t, j.ErrInvalidKeyOps, err) {
			return
		}
	} // Shouldn't allow mixing of ops with different purposes
	l := []j.JWKKeyOpFlag{j.Ops_Sign, j.Ops_Verify}
	r := []j.JWKKeyOpFlag{} // TODO: Check these as features are implemented
	for _, lv := range l {
		for _, rv := range r {
			test(lv | rv)
		}
	}
}

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
	token, err := jwt.GetToken()
	ExpectNilError(t, "Making sample jwt", err)
	jwt_parsed, err := j.Decode(token)
	if !ExpectError(t, j.ErrInvalidAlgorithm, err) {
		return
	}
	if !ExpectErrors(t, jwt_parsed.GetErrors(), j.ErrInvalidAlgorithm) {
		return
	}
}

func Test_Should_decode_allowed_none_algo(t *testing.T) {
	jwt := j.New(rem_none)
	token, err := jwt.GetToken()
	ExpectNilError(t, "Making sample jwt", err)
	_, err = j.Decode(token, rem_none)
	if !ExpectNilError(t, "Decode token with none algo", err) {
		return
	}
}

func Test_Should_build_and_parse_valid_token(t *testing.T) {
	jwt := j.New(
		j.UseConstraints(j.CONST_None_Algo),
		j.Id(fmt.Sprintf("%X", uint64(3000))),
	)
	if !ExpectNilErrors(t, "Build valid token", jwt.GetErrors()) {
		return
	}
	token, err := jwt.GetToken()
	ExpectNilError(t, "Making sample jwt", err)
	jwt_parsed, err := j.Decode(token, rem_none)
	if !ExpectNilError(t, "Parsing jwt token", err) {
		return
	}
	if !jwt.Equals(jwt_parsed) {
		t.Errorf("Expected [\n%#v\n] but was [\n%#v\n]", jwt, jwt_parsed)
		return
	}
}

// Utility function tests

func Test_Should_clone_payload(t *testing.T) {
	jwt := j.New(j.Id("10"))
	p := jwt.GetPayload()

	Equals(t, "10", p.Id, "Should have cloned data into new payload")
}

func Test_Should_clone_map(t *testing.T) {
	m := make(map[string]interface{})
	m["key1"] = "value1"

	var m2 map[string]interface{}
	j.CloneMap(m, &m2)

	Equals(t, "value1", m["key1"], "Should have retained initial values")
	Equals(t, "value1", m2["key1"], "Should have cloned values into new map")

	m2["key1"] = "value2"

	Equals(t, "value1", m["key1"], "Should have retained initial values after update")
	Equals(t, "value2", m2["key1"], "Should have modifeid values in new map")

	m["key1"] = "value3"

	Equals(t, "value3", m["key1"], "Should have modifeid values in old map")
	Equals(t, "value2", m2["key1"], "Should have retained initial values after update")
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
