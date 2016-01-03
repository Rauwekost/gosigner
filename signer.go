package gosigner

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"hash"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"
)

//defaultMaxLife default to 15 minutes
const defaultMaxLife = 900

//Signer type to create signatures
type Signer struct {
	h              hash.Hash
	nonceParam     string
	timestampParam string
	signatureParam string
	checkNonceFunc NonceChecker
	maxLife        int64
}

//Options for the Signer
type Options struct {
	NonceParam     string
	TimestampParam string
	SignatureParam string
	CheckNonceFunc NonceChecker
	MaxLife        int64
}

//NonceChecker is a func type to check if a nonce is valid
type NonceChecker func(n string) error

//defaultCheckNonceFunc is a default fallback function
func defaultCheckNonceFunc(n string) error {
	return nil
}

//New creates a new Signer instance
func New(h hash.Hash, o Options) *Signer {
	if o.NonceParam == "" {
		o.NonceParam = "nonce"
	}
	if o.TimestampParam == "" {
		o.TimestampParam = "timestamp"
	}
	if o.SignatureParam == "" {
		o.SignatureParam = "signature"
	}
	if o.CheckNonceFunc == nil {
		o.CheckNonceFunc = defaultCheckNonceFunc
	}
	if o.MaxLife == 0 {
		o.MaxLife = defaultMaxLife
	}
	return &Signer{
		h:              h,
		nonceParam:     o.NonceParam,
		timestampParam: o.TimestampParam,
		signatureParam: o.SignatureParam,
		checkNonceFunc: o.CheckNonceFunc,
		maxLife:        o.MaxLife,
	}
}

//Sign signs a request with a nonce and timestamp
func (s *Signer) Sign(r *http.Request) {
	t := time.Now().Unix()
	n := s.GenerateNonce(t, "x", "y")
	values := r.URL.Query()
	values.Add(s.nonceParam, n)
	values.Add(s.timestampParam, strconv.Itoa(int(t)))
	r.URL.RawQuery = values.Encode()
	signature := s.Signature(r)

	//add signature to request
	values.Add(s.signatureParam, signature)
	r.URL.RawQuery = values.Encode()
}

//IsValid checks if a request has a valid signature
func (s *Signer) IsValid(r *http.Request) error {
	nonce := r.URL.Query().Get(s.nonceParam)
	signature := r.URL.Query().Get(s.signatureParam)
	timestamp, err := strconv.Atoi(r.URL.Query().Get(s.timestampParam))
	if err != nil {
		return fmt.Errorf("gosigner: Can't convert timestamp to int: %s", err.Error())
	}
	if err := s.checkNonceFunc(nonce); err != nil {
		return fmt.Errorf("gosigner: Invalid nonce: %s", err.Error())
	}
	if (int64(timestamp) + int64(s.maxLife)) < int64(time.Now().Unix()) {
		return fmt.Errorf("gosigner: Maxlife for request reached: %v", r)
	}
	if s.Signature(r) != signature {
		return fmt.Errorf("gosigner: Invalid signature: %s", signature)
	}
	return nil
}

//Signature returns a generated signature for a request. it omits the signature
//query parameter if present
func (s *Signer) Signature(r *http.Request) string {
	s.h.Reset()
	s.h.Write(s.createBaseSignature(r))
	return base64.StdEncoding.EncodeToString(s.h.Sum(nil))
}

//GenerateNonce creates a new nonce based on a timestamp and a number of arguments
func (s *Signer) GenerateNonce(timestamp int64, args ...interface{}) string {
	str := fmt.Sprint(args...)
	str = fmt.Sprintf("%s%d", str, timestamp)
	hash := sha1.New()
	return fmt.Sprintf("%x", hash.Sum([]byte(str)))
}

//createBaseSignature is a helper function to concat all values used in the
//signature
func (s *Signer) createBaseSignature(r *http.Request) []byte {
	return []byte(r.Method + s.concatQueryParameters(r.URL.Query()))
}

//concatQueryParameters sorts and  concatinates query parameters
func (s *Signer) concatQueryParameters(values url.Values) string {
	str := ""
	keys := s.sortedQueryKeys(values)
	for _, k := range keys {
		if k == s.signatureParam {
			continue
		}
		str = fmt.Sprintf("%s%s", str, values.Get(k))
	}
	return str
}

//sortedQueryKeys is a helper function that sorts the url query alphabetically
func (s *Signer) sortedQueryKeys(values url.Values) []string {
	keys := make([]string, 0, len(values))
	for k, _ := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
