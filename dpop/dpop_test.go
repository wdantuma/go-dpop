package dpop

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/zitadel/oidc/v2/pkg/oidc"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func finalHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Final handler executed"))
}

func createDPoPHeader(uri string, method string, headerType jose.ContentType, issuedAt time.Time, nonce string, noClaims bool, addJwk bool) string {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	key := jose.SigningKey{Algorithm: jose.ES256, Key: privateKey}

	signerOpts := jose.SignerOptions{EmbedJWK: addJwk}
	signerOpts.WithType(headerType)
	rsaSigner, err := jose.NewSigner(key, &signerOpts)
	if err != nil {
		panic(err)
	}

	builder := jwt.Signed(rsaSigner)
	if !noClaims {
		iat := issuedAt
		builder = builder.Claims(dPopPayload{
			TokenId:    "ID1",
			HttpMethod: method,
			HttpUri:    uri,
			IssuedAt:   iat.UTC().Unix(),
			Nonce:      nonce,
		})
	}

	header, err := builder.CompactSerialize()
	if err != nil {
		panic(err)
	}
	return header
}

func getRequest(t *testing.T, uri string, method string) *http.Request {
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(method, uri, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RequestURI = u.RequestURI()
	return req
}

func checkResult(t *testing.T, rr *httptest.ResponseRecorder, expectErrortype string, expectErrorDescription string, expectHttpStatus int) {
	if expectHttpStatus != http.StatusOK {
		result := oidc.Error{}
		err := json.Unmarshal(rr.Body.Bytes(), &result)
		if err != nil {
			t.Errorf("handler returned no json")
		}
		if result.ErrorType != dPopError {
			t.Errorf("handler returned errortype %v expected %v", result.ErrorType, expectErrortype)
		}
		if result.Description != expectErrorDescription {
			t.Errorf("handler returned error description %v expected %v", result.Description, expectErrorDescription)
		}
	}
	if status := rr.Code; status != expectHttpStatus {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusBadRequest)
	}
}

func TestNoDPoPHeader(t *testing.T) {
	rr := httptest.NewRecorder()

	req := getRequest(t, "http://test.com/test", "get")

	handler := http.HandlerFunc(finalHandler)

	DPoPInterceptor(handler).ServeHTTP(rr, req)

	checkResult(t, rr, "", "", http.StatusOK)

	if bytes.Compare(rr.Body.Bytes(), []byte("Final handler executed")) != 0 {
		t.Errorf("Final handler not executed")
	}

}

func TestValidDPoPHeader(t *testing.T) {
	rr := httptest.NewRecorder()

	req := getRequest(t, "http://test.com/test", "get")

	req.Header.Set(dPoPHeaderKey, createDPoPHeader("http://test.com/test", "get", dPopJwtHeaderType, time.Now(), "", false, true))

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Context().Value(DPopThumbprint) == nil {
			t.Errorf("Missing thumbprint in context")
		}
	})

	DPoPInterceptor(handler).ServeHTTP(rr, req)

	checkResult(t, rr, "", "", http.StatusOK)

}

func TestMultipleDPopHeader(t *testing.T) {

	rr := httptest.NewRecorder()

	req := getRequest(t, "http://test.com/test", "get")

	req.Header.Add(dPoPHeaderKey, createDPoPHeader("http://test.com/test", "get", dPopJwtHeaderType, time.Now(), "", false, true))
	req.Header.Add(dPoPHeaderKey, createDPoPHeader("http://test.com/test", "get", dPopJwtHeaderType, time.Now(), "", false, true))

	handler := http.HandlerFunc(finalHandler)

	DPoPInterceptor(handler).ServeHTTP(rr, req)

	checkResult(t, rr, dPopError, notAValidJWT, http.StatusBadRequest)
}

func TestJWT(t *testing.T) {

	rr := httptest.NewRecorder()

	req := getRequest(t, "http://test.com/test", "get")

	req.Header.Set(dPoPHeaderKey, "Not wellformed JWT")

	handler := http.HandlerFunc(finalHandler)

	DPoPInterceptor(handler).ServeHTTP(rr, req)

	checkResult(t, rr, dPopError, notAValidJWT, http.StatusBadRequest)
}

func TestMissingClaims(t *testing.T) {
	rr := httptest.NewRecorder()

	req := getRequest(t, "http://test.com/test", "get")

	req.Header.Set(dPoPHeaderKey, createDPoPHeader("http://test.com/test", "get", dPopJwtHeaderType, time.Now(), "", true, true))

	handler := http.HandlerFunc(finalHandler)

	DPoPInterceptor(handler).ServeHTTP(rr, req)

	checkResult(t, rr, dPopError, missingClaims, http.StatusBadRequest)
}

func TestWrongHeaderType(t *testing.T) {
	rr := httptest.NewRecorder()

	req := getRequest(t, "http://test.com/test", "get")

	req.Header.Set(dPoPHeaderKey, createDPoPHeader("http://test.com/test", "get", "JWT", time.Now(), "", false, true))

	handler := http.HandlerFunc(finalHandler)

	DPoPInterceptor(handler).ServeHTTP(rr, req)

	checkResult(t, rr, dPopError, invalidDPoPHeader, http.StatusBadRequest)
}

func TestWrongMethod(t *testing.T) {
	rr := httptest.NewRecorder()

	req := getRequest(t, "http://test.com/test", "post")

	req.Header.Set(dPoPHeaderKey, createDPoPHeader("http://test.com/test", "get", dPopJwtHeaderType, time.Now(), "", false, true))

	handler := http.HandlerFunc(finalHandler)

	DPoPInterceptor(handler).ServeHTTP(rr, req)

	checkResult(t, rr, dPopError, wrongMethodOrUri, http.StatusBadRequest)
}

func TestWrongUri(t *testing.T) {
	rr := httptest.NewRecorder()

	req := getRequest(t, "http://test.com/test", "gest")

	req.Header.Set(dPoPHeaderKey, createDPoPHeader("http://test.com/notest", "get", dPopJwtHeaderType, time.Now(), "", false, true))

	handler := http.HandlerFunc(finalHandler)

	DPoPInterceptor(handler).ServeHTTP(rr, req)

	checkResult(t, rr, dPopError, wrongMethodOrUri, http.StatusBadRequest)
}

func TestIssuedInFuture(t *testing.T) {
	rr := httptest.NewRecorder()

	req := getRequest(t, "http://test.com/test", "get")

	iat := time.Now().Add(time.Second)
	req.Header.Set(dPoPHeaderKey, createDPoPHeader("http://test.com/test", "get", dPopJwtHeaderType, iat, "", false, true))

	handler := http.HandlerFunc(finalHandler)

	DPoPInterceptor(handler).ServeHTTP(rr, req)

	checkResult(t, rr, dPopError, missingClaims, http.StatusBadRequest)

}

func TestMissingJwk(t *testing.T) {
	rr := httptest.NewRecorder()

	req := getRequest(t, "http://test.com/test", "get")

	req.Header.Set(dPoPHeaderKey, createDPoPHeader("http://test.com/test", "get", dPopJwtHeaderType, time.Now(), "", false, false))

	handler := http.HandlerFunc(finalHandler)

	DPoPInterceptor(handler).ServeHTTP(rr, req)

	checkResult(t, rr, dPopError, invalidDPoPHeader, http.StatusBadRequest)

}

func TestNonce(t *testing.T) {
	rr := httptest.NewRecorder()

	req := getRequest(t, "http://test.com/test", "get")

	req.Header.Set(dPoPHeaderKey, createDPoPHeader("http://test.com/test", "get", dPopJwtHeaderType, time.Now(), "Nonce not allowed", false, true))

	handler := http.HandlerFunc(finalHandler)

	DPoPInterceptor(handler).ServeHTTP(rr, req)

	checkResult(t, rr, dPopError, missingClaims, http.StatusBadRequest)

}
