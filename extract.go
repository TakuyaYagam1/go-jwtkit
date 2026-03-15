package jwt

import (
	"net/http"
	"strings"
)

const bearerPrefixLen = 7

// ExtractRaw returns the raw JWT string from the Authorization: Bearer header, or "" if missing or invalid.
// The scheme name is compared case-insensitively per RFC 6750.
func ExtractRaw(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) >= bearerPrefixLen && strings.EqualFold(h[:bearerPrefixLen], "Bearer ") {
		return strings.TrimSpace(h[bearerPrefixLen:])
	}
	return ""
}

// ExtractRawFromCookie returns the raw token from the named cookie, or "" if missing.
func ExtractRawFromCookie(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil || c == nil {
		return ""
	}
	return strings.TrimSpace(c.Value)
}
