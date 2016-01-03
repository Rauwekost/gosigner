package gosigner

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"testing"
	"time"
)

var secret = "secret"
var options = Options{
	NonceParam:     "nonce",
	TimestampParam: "timestamp",
	SignatureParam: "signature",
	MaxLife:        900,
}

func getSigner() *Signer {
	h := hmac.New(sha1.New, []byte(secret))
	return New(h, options)
}

func TestNew(t *testing.T) {
	signer := getSigner()
	r, _ := http.NewRequest("POST", "http://robhar.xyz?foo=bar", nil)
	signer.Sign(r)

	if r.URL.Query().Get(options.TimestampParam) == "" {
		t.Fatalf("timestamp not added to request %+v", r)
	}

	if r.URL.Query().Get(options.NonceParam) == "" {
		t.Fatalf("nonce not added to request %+v", r)
	}

	if r.URL.Query().Get(options.SignatureParam) == "" {
		t.Fatalf("signature not added to request %+v", r)
	}
}

func TestConcatQueryParameters(t *testing.T) {
	signer := getSigner()
	values := url.Values{}
	values.Add("foo", "bar")
	values.Add("baz", "boz")
	values.Add("timestamp", "14093294990")
	values.Add("nonce", "1usdfIHOOH#$B3NGP12NGIDIEFN3232IGP")
	concat := signer.concatQueryParameters(values)
	expect := "bozbar1usdfIHOOH#$B3NGP12NGIDIEFN3232IGP14093294990"
	if expect != concat {
		t.Fatalf("concat failed expected: %s got: %s", expect, concat)
	}
}

func TestSorting(t *testing.T) {
	signer := getSigner()
	values := url.Values{}
	values.Add("foo", "bar")
	values.Add("baz", "boz")
	values.Add("timestamp", "14093294990")
	values.Add("nonce", "1usdfIHOOH#$B3NGP12NGIDIEFN3232IGP")
	sorted := signer.sortedQueryKeys(values)
	expect := []string{"baz", "foo", "nonce", "timestamp"}
	if !reflect.DeepEqual(expect, sorted) {
		t.Fatalf("concat failed expected: %s got: %s", expect, sorted)
	}
}

func TestValidation(t *testing.T) {
	signer := getSigner()
	r, _ := http.NewRequest("POST", "http://robhar.xyz?foo=bar", nil)
	signer.Sign(r)

	if err := signer.IsValid(r); err != nil {
		t.Fatalf("Signature validation failed %s", err.Error())
	}
}

func TestMaxLifeValidation(t *testing.T) {
	o := options
	o.MaxLife = 1
	h := hmac.New(md5.New, []byte(secret))
	signer := New(h, o)

	r, _ := http.NewRequest("POST", "http://robhar.xyz?foo=bar", nil)
	signer.Sign(r)

	time.Sleep(2 * time.Second)
	if err := signer.IsValid(r); err == nil {
		t.Fatal("this signature should be out-dated")
	}
}

func TestCheckNonceFunc(t *testing.T) {
	o := options
	o.CheckNonceFunc = func(n string) error {
		return errors.New("nonce already used")
	}
	h := hmac.New(md5.New, []byte(secret))
	signer := New(h, o)

	r, _ := http.NewRequest("POST", "http://robhar.xyz?foo=bar", nil)
	signer.Sign(r)
	if err := signer.IsValid(r); err == nil {
		t.Fatal("this signature check should fail because of invalid nonce")
	}
}
