Go Signer
=========
A simple url signer written in go.

##Signatures
A signature must contain a <code>nonce</code>, <code>timestamp</code> and
<code>signature</code>. The keys can be configured in the options.

The signature is composed as follows:

```
Method+(parameters sorted alphabetically including nonce and timestamp)
```

example:
```
POSTsomeparametersconcatedalphabeticallyNONCE1451852213
```

##Nonce check function
You can pass a nonce check function. You'll have to store the used nonces
yourself and implement the CheckNonceFunc to check if the nonce exists.

```
func CheckNonce(n string) error
```

##Example Usage
```
var secret = "secret"
var options = gosigner.Options{
	NonceParam:     "nonce",
	TimestampParam: "timestamp",
	SignatureParam: "signature",
	MaxLife:        900, //max life in seconds
}

h := hmac.New(sha1.New, []byte(secret))
signer :=  gosigner.New(h, options)

r, _ := http.NewRequest("GET", "http://google.com?foo=bar", nil)
signer.Sign(r)

if err := signer.IsValid(r); err != nil {
	//signature is invalid
}
```



