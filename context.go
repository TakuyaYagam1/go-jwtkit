package jwt

import (
	"context"

	"github.com/google/uuid"
)

type claimsContextKey struct{}

// ClaimsIntoContext stores claims in ctx. Use with JWTAuth middleware or after ValidateAccessToken.
func ClaimsIntoContext(ctx context.Context, c *CustomClaims) context.Context {
	return context.WithValue(ctx, claimsContextKey{}, c)
}

// ClaimsFromContext returns the CustomClaims from ctx, or (nil, false) if not set or nil.
func ClaimsFromContext(ctx context.Context) (*CustomClaims, bool) {
	c, ok := ctx.Value(claimsContextKey{}).(*CustomClaims)
	return c, ok && c != nil
}

// UserIDFromContext returns the user ID from claims in ctx, or (uuid.Nil, false) if not set or invalid.
func UserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	c, ok := ClaimsFromContext(ctx)
	if !ok || c == nil {
		return uuid.Nil, false
	}
	id, err := uuid.Parse(c.UserID)
	if err != nil {
		return uuid.Nil, false
	}
	return id, true
}

// RoleFromContext returns the role from claims in ctx, or ("", false) if not set.
func RoleFromContext(ctx context.Context) (string, bool) {
	c, ok := ClaimsFromContext(ctx)
	if !ok || c == nil {
		return "", false
	}
	return c.Role, true
}
