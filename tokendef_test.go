package jose_test

import (
	. "github.com/stretchr/testify/assert"
	j "github.com/vizidrix/jose"
	"testing"
)

func AssertClaims(t *testing.T, expected, actual map[string]interface{}, args ...interface{}) bool {
	if !Equal(t, len(expected), len(actual), "invalid set of private claims") {
		return false
	}
	for ek, ev := range expected {
		av, ok := actual[ek]
		if !True(t, ok, "expected key [ %s ] but not found in [\n%#v\n]", ek, actual) ||
			!Equal(t, ev, av, "expected key to match") {
			return false
		}

	}
	return true
}

func NoErrors(t *testing.T, errs []error, args ...interface{}) bool {
	if !Nil(t, errs, args...) || !Len(t, errs, 0, args...) {
		return false
	}
	return true
}

func Errors(t *testing.T, errs []error, expected []error, args ...interface{}) bool {
	if !Len(t, errs, len(expected), args...) {
		return false
	}
	for i, _ := range errs {
		if !EqualError(t, errs[i], expected[i].Error(), args...) {
			return false
		}
	}
	return true
}

func Test__Return_no_errors(t *testing.T) {
	jwt := j.New(j.RemoveConstraints(j.CONST_None_Algo))
	errs := jwt.GetErrors()
	NoErrors(t, errs, "%s", errs)
}

func Test__Error_for_uninitialized_token(t *testing.T) {
	jwt := j.NewEmptyToken()
	errs := jwt.GetErrors()
	Errors(t, errs, []error{j.ErrUnitializedToken}, "%s", errs)
}

func Test__Error_for_nil_pointer(t *testing.T) {
	var jwt *j.TokenDef
	errs := jwt.GetErrors()
	Errors(t, errs, []error{j.ErrRequiredElementWasNil}, "%s", errs)
}

func Test__Append_private_claims(t *testing.T) {
	expected := map[string]interface{}{
		"a": "a-1",
		"b": "b-1",
	}

	jwt := j.New(rem_none,
		j.PrivateClaims(expected))
	if NoErrors(t, jwt.GetErrors(), "append private claims") && AssertClaims(t, expected, jwt.GetPrivateClaims()) {
		return
	}
}

func Test__Append_public_claims_to_both_private_and_public(t *testing.T) {
	expected := map[string]interface{}{
		"a": "a-1",
		"b": "b-1",
	}

	jwt := j.New(rem_none,
		j.PublicClaims(expected))
	if NoErrors(t, jwt.GetErrors(), "append public claims") &&
		AssertClaims(t, expected, jwt.GetPrivateClaims()) &&
		AssertClaims(t, expected, jwt.GetPublicClaims()) {
		return
	}
}

func Test__Return_error_when_overwriting_private_claims_on_set(t *testing.T) {
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
	if !Errors(t, jwt.GetErrors(), []error{j.ErrClaimOverwritten}) {
		return
	}
}

func Test__Return_error_when_overwriting_public_claims_on_set(t *testing.T) {
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
	if !Errors(t, jwt.GetErrors(), []error{j.ErrClaimOverwritten}) {
		return
	}
}

func Test__Overwrite_found_claims_on_set_with_relaxed_options(t *testing.T) {
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
	if !NoErrors(t, jwt.GetErrors(), "Overwrite exsiting claims relaxed") {
		return
	}
	AssertClaims(t, expected, jwt.GetPrivateClaims())
}

func Test__Swap_found_public_claims_on_set_with_relaxed_options(t *testing.T) {
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
	if !NoErrors(t, jwt.GetErrors(), "swap exsiting public claims relaxed") {
		return
	}
	AssertClaims(t, expected_priv, jwt.GetPrivateClaims())
	AssertClaims(t, expected_pub, jwt.GetPublicClaims())
}

func Test__Swap_found_private_claims_on_set_with_relaxed_options(t *testing.T) {
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
	if !NoErrors(t, jwt.GetErrors(), "swap exsiting public claims relaxed") {
		return
	}
	AssertClaims(t, expected_priv, jwt.GetPrivateClaims())
	AssertClaims(t, expected_pub, jwt.GetPublicClaims())
}

func Test__Merge_public_claims_into_private_set_for_SetClaims(t *testing.T) {
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
	if !NoErrors(t, jwt.GetErrors(), "Merge public claims") {
		return
	}
	AssertClaims(t, expected_priv, jwt.GetPrivateClaims())
	AssertClaims(t, expected_pub, jwt.GetPublicClaims())
}

func Test__Return_error_when_private_claims_are_set_public(t *testing.T) {
	claims := map[string]interface{}{
		"a": "a-1",
	}

	jwt := j.New(rem_none,
		j.PrivateClaims(claims),
		j.PublicClaims(claims))
	if !Errors(t, jwt.GetErrors(), []error{j.ErrClaimOverwritten}) {
		return
	}
}

func Test__Return_error_when_overwriting_public_claims_with_private(t *testing.T) {
	claims := map[string]interface{}{
		"a": "a-1",
	}

	jwt := j.New(rem_none,
		j.PublicClaims(claims),
		j.PrivateClaims(claims))
	if !Errors(t, jwt.GetErrors(), []error{j.ErrClaimOverwritten}) {
		return
	}
}
