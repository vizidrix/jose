package jose_test

import (
	j "github.com/vizidrix/jose"
	"testing"
)

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
	AssertClaims(t, expected, jwt.GetPrivateClaims())
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
	AssertClaims(t, expected, jwt.GetPrivateClaims())
	AssertClaims(t, expected, jwt.GetPublicClaims())
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
		j.RemoveConstraints(j.CONST_Overwrite_Private),
		j.PrivateClaims(initial),
		j.PrivateClaims(overwrite))
	if !ExpectNilErrors(t, "Overwrite exsiting claims relaxed", jwt.GetErrors()) {
		return
	}
	AssertClaims(t, expected, jwt.GetPrivateClaims())
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
		j.RemoveConstraints(j.CONST_Swap_Public),
		j.PublicClaims(initial),
		j.PrivateClaims(overwrite))
	if !ExpectNilErrors(t, "swap exsiting public claims relaxed", jwt.GetErrors()) {
		return
	}
	AssertClaims(t, expected_priv, jwt.GetPrivateClaims())
	AssertClaims(t, expected_pub, jwt.GetPublicClaims())
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
		j.RemoveConstraints(j.CONST_Swap_Private),
		j.PrivateClaims(initial),
		j.PublicClaims(overwrite))
	if !ExpectNilErrors(t, "swap exsiting public claims relaxed", jwt.GetErrors()) {
		return
	}
	AssertClaims(t, expected_priv, jwt.GetPrivateClaims())
	AssertClaims(t, expected_pub, jwt.GetPublicClaims())
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
	AssertClaims(t, expected_priv, jwt.GetPrivateClaims())
	AssertClaims(t, expected_pub, jwt.GetPublicClaims())
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
