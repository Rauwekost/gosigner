package gosigner

import "net/http"

type SignerMiddleware struct {
	signer       *Signer
	errorHandler func(w http.ResponseWriter, err error)
}

func defaultErrHandler(w http.ResponseWriter, err error) {
	w.WriteHeader(403)
	w.Write([]byte("forbidden"))
}

func NewMidddleware(s *Signer, errorHandler func(w http.ResponseWriter, err error)) *SignerMiddleware {
	if errorHandler == nil {
		errorHandler = defaultErrHandler
	}
	return &SignerMiddleware{
		signer:       s,
		errorHandler: errorHandler,
	}
}

func (s *SignerMiddleware) Handler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if err := s.signer.IsValid(r); err != nil {
			s.errorHandler(w, err)
			return
		}
		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}
