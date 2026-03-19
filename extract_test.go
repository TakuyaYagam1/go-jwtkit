package jwtkit

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractRaw(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest("GET", "/", nil)
	assert.Empty(t, ExtractRaw(req))
	req.Header.Set("Authorization", "Bearer abc123")
	assert.Equal(t, "abc123", ExtractRaw(req))
	req.Header.Set("Authorization", "Bearer  ")
	assert.Equal(t, "", ExtractRaw(req))
}

func TestExtractRawFromCookie(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("GET", "/", nil)
	assert.Empty(t, ExtractRawFromCookie(r, "token"))
	r.AddCookie(&http.Cookie{Name: "token", Value: "abc"})
	assert.Equal(t, "abc", ExtractRawFromCookie(r, "token"))
	r = httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "token", Value: "  x  "})
	assert.Equal(t, "x", ExtractRawFromCookie(r, "token"))
	r = httptest.NewRequest("GET", "/", nil)
	assert.Empty(t, ExtractRawFromCookie(r, "other"))
}
