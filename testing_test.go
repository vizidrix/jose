package jose_test

import (
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

var failnow = false

func fail(tb testing.TB) {
	if failnow {
		tb.FailNow()
	} else {
		tb.Fail()
	}
}

// fails the test if the condition is false.
func Assert(tb testing.TB, condition bool, msg string, v ...interface{}) {
	if !condition {
		_, file, line, _ := runtime.Caller(1)
		fmt.Printf("\033[31m%s:%d: "+msg+"\033[39m\n\n", append([]interface{}{filepath.Base(file), line}, v...)...)
		fail(tb)
	}
}

// fails the test if an err is nil.
func Ok(tb testing.TB, err error) {
	if err != nil {
		_, file, line, _ := runtime.Caller(1)
		fmt.Printf("\033[31m%s:%d: unexpected error: %s\033[39m\n\n", filepath.Base(file), line, err.Error())
		fail(tb)
	}
}

// fails the test if an err is not nil.
func NotOk(tb testing.TB, err error) {
	if err == nil {
		_, file, line, _ := runtime.Caller(1)
		fmt.Printf("\033[31m%s:%d: unexpected error: %s\033[39m\n\n", filepath.Base(file), line, err.Error())
		fail(tb)
	}
}

// fails the test if exp is not equal to act.
func Equals(tb testing.TB, exp, act interface{}, msg string, v ...interface{}) {
	if !reflect.DeepEqual(exp, act) {
		_, file, line, _ := runtime.Caller(1)
		fmt.Printf("\033[31m%s:%d:\n[\n%s\n]\n\n\n\texp: %#v\n\n\tgot: %#v\033[39m\n\n", filepath.Base(file), line, fmt.Sprintf(msg, v...), exp, act)
		fail(tb)
	}
}

// fails the test if exp is equal to act.
func NotEquals(tb testing.TB, exp, act interface{}, msg string, v ...interface{}) {
	if reflect.DeepEqual(exp, act) {
		_, file, line, _ := runtime.Caller(1)
		fmt.Printf("\033[31m%s:%d:\n[\n%s\n]\n\n\n\texp: %#v\n\n\tgot: %#v\033[39m\n\n", filepath.Base(file), line, fmt.Sprintf(msg, v...), exp, act)
		fail(tb)
	}
}

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
