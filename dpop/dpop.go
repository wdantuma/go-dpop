// implementation of https://datatracker.ietf.org/doc/html/rfc9449

package dpop

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"strings"
	"time"

	b64 "encoding/base64"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	DPoPHeaderKey     = "DPoP"
	dPopError         = "invalid_dpop_proof"
	dPopJwtHeaderType = "dpop+jwt"
	DPopThumbprint    = "DPoPThumbprint"
	notAValidJWT      = "Not a valid JWT"
	invalidSignature  = "Invalid signature"
	invalidDPoPHeader = "invalid DPoP header"
	missingClaims     = "Missing DPoP claims, invalid issued at or invalid nonce"
	wrongMethodOrUri  = "Wrong HTTP method or uri"
)

type dPopPayload struct {
	TokenId         string `json:"jti"`
	IssuedAt        int64  `json:"iat"`
	HttpMethod      string `json:"htm"`
	HttpUri         string `json:"htu"`
	AccessTokenHash string `json:"ath"`
	Nonce           string `json:"nonce"`
}

func isValidDPoPHeader(headers []jose.Header) bool {
	if len(headers) != 1 {
		return false
	}

	if headers[0].ExtraHeaders == nil || len(headers[0].ExtraHeaders) > 0 && headers[0].ExtraHeaders[jose.HeaderType] != dPopJwtHeaderType {
		return false
	}
	if headers[0].JSONWebKey == nil {
		return false
	}
	return true
}

func isValidDPoPPayload(payload *dPopPayload) bool {
	var timeNow = time.Now().UTC()
	var time5MinAgo = time.Now().Add(-5 * time.Minute).UTC()
	var issuedAt = time.Unix(payload.IssuedAt, 0).UTC()
	if issuedAt.After(timeNow) { // not in the future
		return false
	}
	if issuedAt.Before(time5MinAgo) { // no older then 5 min
		return false
	}

	if payload.TokenId == "" || payload.HttpMethod == "" || payload.HttpUri == "" {
		return false
	}
	if payload.Nonce != "" {
		return false // nonce not yet supported
	}
	return true
}

func isValidMethodAndUri(payload *dPopPayload, r *http.Request) bool {
	if !strings.EqualFold(payload.HttpMethod, r.Method) {
		return false
	}
	method := "https"
	if r.TLS == nil {
		method = "http"
	}
	requestUri := fmt.Sprintf("%s://%s%s", method, r.Host, r.RequestURI)
	if !strings.EqualFold(payload.HttpUri, requestUri) {
		log.Println(payload.HttpUri)
		log.Println(requestUri)
		return false
	}
	return true
}

func getThumbprint(webkey jose.JSONWebKey, alg jose.SignatureAlgorithm) ([]byte, error) {

	var hash crypto.Hash
	switch alg {
	case jose.ES256, jose.RS256:
		hash = crypto.SHA256
	case jose.ES384, jose.RS384:
		hash = crypto.SHA384
	case jose.ES512, jose.RS512:
		hash = crypto.SHA512
	default:
		return nil, errors.New("Unsupported algorithm")
	}
	return webkey.Thumbprint(hash)
}

type dPoPRequest struct {
	*http.Request
	string
}

func checkDPop(h http.Handler, w http.ResponseWriter, r *http.Request) error {
	dPopHeaders := r.Header.Values(DPoPHeaderKey)
	if len(dPopHeaders) == 0 {
		h.ServeHTTP(w, r) // call original
		return nil
	} else {
		if len(dPopHeaders) != 1 || dPopHeaders[0] == "" || len(dPopHeaders[0]) < 3 {
			return errors.New(notAValidJWT)
		}
		dPopHeader := dPopHeaders[0]
		dPopJwt, jwterr := jwt.ParseSigned(dPopHeader)
		dPopJws, jwserr := jose.ParseSigned(dPopHeader)
		if jwterr != nil || jwserr != nil {
			return errors.New(notAValidJWT)
		}
		if !isValidDPoPHeader(dPopJwt.Headers) {
			return errors.New(invalidDPoPHeader)
		}
		rawPayload, err := dPopJws.Verify((dPopJwt.Headers[len(dPopJwt.Headers)-1].JSONWebKey.Public()))
		if err != nil {
			return errors.New(invalidSignature)
		}
		payload := dPopPayload{}
		json.Unmarshal(rawPayload, &payload)
		if !isValidDPoPPayload(&payload) {
			return errors.New(missingClaims)
		}
		if !isValidMethodAndUri(&payload, r) {
			return errors.New(wrongMethodOrUri)
		}
		jwtHeader := dPopJwt.Headers[len(dPopJwt.Headers)-1]
		public := jwtHeader.JSONWebKey.Public()
		thumbPrint, err := getThumbprint(public, jose.SignatureAlgorithm(jwtHeader.Algorithm))
		if err != nil {
			return err
		}
		req := r.WithContext(context.WithValue(r.Context(), DPopThumbprint, b64.URLEncoding.WithPadding(b64.NoPadding).EncodeToString(thumbPrint)))
		h.ServeHTTP(w, req) // call original
		return nil
	}
}

func MarshalJSON(w http.ResponseWriter, i any) {
	MarshalJSONWithStatus(w, i, http.StatusOK)
}

func MarshalJSONWithStatus(w http.ResponseWriter, i any, status int) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	if i == nil || (reflect.ValueOf(i).Kind() == reflect.Ptr && reflect.ValueOf(i).IsNil()) {
		return
	}
	err := json.NewEncoder(w).Encode(i)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type errorType string

type Error struct {
	Parent           error     `json:"-" schema:"-"`
	ErrorType        errorType `json:"error" schema:"error"`
	Description      string    `json:"error_description,omitempty" schema:"error_description,omitempty"`
	State            string    `json:"state,omitempty" schema:"state,omitempty"`
	redirectDisabled bool      `schema:"-"`
}

func DPoPInterceptor(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := checkDPop(h, w, r)
		if err != nil {
			MarshalJSONWithStatus(w, &Error{ErrorType: dPopError, Description: err.Error()}, http.StatusBadRequest)
		}
	})
}
