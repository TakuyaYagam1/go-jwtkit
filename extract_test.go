package jwt_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	jwt "github.com/TakuyaYagam1/go-jwtkit"
)

func TestExtractRawFromCookie(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("GET", "/", nil)
	assert.Empty(t, jwt.ExtractRawFromCookie(r, "token"))
	r.AddCookie(&http.Cookie{Name: "token", Value: "abc"})
	assert.Equal(t, "abc", jwt.ExtractRawFromCookie(r, "token"))
	r = httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "token", Value: "  x  "})
	assert.Equal(t, "x", jwt.ExtractRawFromCookie(r, "token"))
	r = httptest.NewRequest("GET", "/", nil)
	assert.Empty(t, jwt.ExtractRawFromCookie(r, "other"))
}
