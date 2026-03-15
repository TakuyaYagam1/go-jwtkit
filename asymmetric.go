package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// AsymmetricKeyEntry holds a key id and RSA or Ed25519 key pair for signing/verification.
type AsymmetricKeyEntry struct {
	Kid        string
	PrivateKey crypto.PrivateKey
	PublicKey  crypto.PublicKey
}

// JWTServiceAsymmetric implements Service using RS256 or EdDSA. Use NewJWTServiceAsymmetric to construct.
type JWTServiceAsymmetric struct {
	accessKeys         []AsymmetricKeyEntry
	refreshKeys        []AsymmetricKeyEntry
	accessPrimaryKid   string
	refreshPrimaryKid  string
	accessTTL          time.Duration
	refreshTTL         time.Duration
	issuer             string
	revoker            RevocationStore
	userRoleLookup     atomic.Pointer[UserRoleLookup]
	accessPublicByKid  map[string]crypto.PublicKey
	refreshPublicByKid map[string]crypto.PublicKey
}

// NewJWTServiceAsymmetric builds a JWT service with RSA (RS256), ECDSA (ES256/ES384/ES512), or Ed25519 (EdDSA) keys.
// Issuer must be non-empty. Revoker and userRoleLookup may be nil.
// Key pairs are validated at construction: RSA requires RSA public key, ECDSA requires ECDSA public key (P-256/P-384/P-521), Ed25519 requires Ed25519 public key.
func NewJWTServiceAsymmetric(
	accessKeys []AsymmetricKeyEntry,
	refreshKeys []AsymmetricKeyEntry,
	accessTTL time.Duration,
	refreshTTL time.Duration,
	issuer string,
	revoker RevocationStore,
	userRoleLookup UserRoleLookup,
) (*JWTServiceAsymmetric, error) {
	if len(accessKeys) == 0 {
		return nil, fmt.Errorf("access keys must contain at least one key")
	}
	if len(refreshKeys) == 0 {
		return nil, fmt.Errorf("refresh keys must contain at least one key")
	}
	if issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}
	for i, k := range accessKeys {
		if k.PrivateKey == nil || k.PublicKey == nil {
			return nil, fmt.Errorf("access key %d: private and public key required", i)
		}
		if err := validateAsymmetricKeyPair(k.PrivateKey, k.PublicKey); err != nil {
			return nil, fmt.Errorf("access key %q: %w", k.Kid, err)
		}
	}
	for i, k := range refreshKeys {
		if k.PrivateKey == nil || k.PublicKey == nil {
			return nil, fmt.Errorf("refresh key %d: private and public key required", i)
		}
		if err := validateAsymmetricKeyPair(k.PrivateKey, k.PublicKey); err != nil {
			return nil, fmt.Errorf("refresh key %q: %w", k.Kid, err)
		}
	}
	accessPub := make(map[string]crypto.PublicKey, len(accessKeys))
	for _, k := range accessKeys {
		accessPub[k.Kid] = k.PublicKey
	}
	refreshPub := make(map[string]crypto.PublicKey, len(refreshKeys))
	for _, k := range refreshKeys {
		refreshPub[k.Kid] = k.PublicKey
	}
	j := &JWTServiceAsymmetric{
		accessKeys:         accessKeys,
		refreshKeys:        refreshKeys,
		accessPrimaryKid:   accessKeys[0].Kid,
		refreshPrimaryKid:  refreshKeys[0].Kid,
		accessTTL:          accessTTL,
		refreshTTL:         refreshTTL,
		issuer:             issuer,
		revoker:            revoker,
		accessPublicByKid:  accessPub,
		refreshPublicByKid: refreshPub,
	}
	if userRoleLookup != nil {
		j.userRoleLookup.Store(&userRoleLookup)
	}
	return j, nil
}

func validateAsymmetricKeyPair(priv crypto.PrivateKey, pub crypto.PublicKey) error {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		if _, ok := pub.(*rsa.PublicKey); !ok {
			return fmt.Errorf("RSA private key requires RSA public key")
		}
		return nil
	case ed25519.PrivateKey:
		if _, ok := pub.(ed25519.PublicKey); !ok {
			return fmt.Errorf("Ed25519 private key requires Ed25519 public key")
		}
		return nil
	case *ecdsa.PrivateKey:
		if _, ok := pub.(*ecdsa.PublicKey); !ok {
			return fmt.Errorf("ECDSA private key requires ECDSA public key")
		}
		switch k.Curve.Params().Name {
		case "P-256", "P-384", "P-521":
			return nil
		default:
			return fmt.Errorf("unsupported ECDSA curve %q (supported: P-256, P-384, P-521)", k.Curve.Params().Name)
		}
	default:
		return fmt.Errorf("unsupported private key type %T (supported: *rsa.PrivateKey, ed25519.PrivateKey, *ecdsa.PrivateKey)", priv)
	}
}

// SetUserRoleLookup sets or replaces the callback used during RefreshTokens to resolve current user data.
func (j *JWTServiceAsymmetric) SetUserRoleLookup(fn UserRoleLookup) {
	j.userRoleLookup.Store(&fn)
}

// GenerateTokenPair issues a new access and refresh token pair for the given user and claims.
func (j *JWTServiceAsymmetric) GenerateTokenPair(ctx context.Context, userID uuid.UUID, email, name, role string) (*TokenPair, error) {
	now := time.Now()
	accessExpiry := now.Add(j.accessTTL)
	refreshExpiry := now.Add(j.refreshTTL)
	accessJTI := uuid.New().String()
	refreshJTI := uuid.New().String()

	accessClaims := &CustomClaims{
		UserID:    userID.String(),
		Email:     email,
		FullName:  name,
		Role:      role,
		TokenType: TokenTypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        accessJTI,
			ExpiresAt: jwt.NewNumericDate(accessExpiry),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    j.issuer,
		},
	}
	refreshClaims := &CustomClaims{
		UserID:    userID.String(),
		Email:     email,
		FullName:  name,
		Role:      role,
		TokenType: TokenTypeRefresh,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        refreshJTI,
			ExpiresAt: jwt.NewNumericDate(refreshExpiry),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    j.issuer,
		},
	}

	accessEntry := j.accessKeys[0]
	accessMethod, err := signingMethodForKey(accessEntry.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("access key: %w", err)
	}
	accessToken := jwt.NewWithClaims(accessMethod, accessClaims)
	accessToken.Header["kid"] = j.accessPrimaryKid
	accessTokenString, err := accessToken.SignedString(accessEntry.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshEntry := j.refreshKeys[0]
	refreshMethod, err := signingMethodForKey(refreshEntry.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("refresh key: %w", err)
	}
	refreshToken := jwt.NewWithClaims(refreshMethod, refreshClaims)
	refreshToken.Header["kid"] = j.refreshPrimaryKid
	refreshTokenString, err := refreshToken.SignedString(refreshEntry.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:      accessTokenString,
		RefreshToken:     refreshTokenString,
		AccessExpiresAt:  accessExpiry.Unix(),
		RefreshExpiresAt: refreshExpiry.Unix(),
	}, nil
}

// ValidateAccessToken parses and validates an access token; checks signature, issuer, type, and revocation.
func (j *JWTServiceAsymmetric) ValidateAccessToken(ctx context.Context, tokenString string) (*CustomClaims, error) {
	return j.validateToken(ctx, tokenString, TokenTypeAccess, j.accessPrimaryKid, j.accessPublicByKid)
}

// ValidateRefreshToken parses and validates a refresh token; checks signature, issuer, type, and revocation.
func (j *JWTServiceAsymmetric) ValidateRefreshToken(ctx context.Context, tokenString string) (*CustomClaims, error) {
	return j.validateToken(ctx, tokenString, TokenTypeRefresh, j.refreshPrimaryKid, j.refreshPublicByKid)
}

func (j *JWTServiceAsymmetric) validateToken(ctx context.Context, tokenString, tokenType, primaryKid string, publicByKid map[string]crypto.PublicKey) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (any, error) {
		switch token.Method.(type) {
		case *jwt.SigningMethodRSA, *jwt.SigningMethodECDSA, *jwt.SigningMethodEd25519:
			kid := primaryKid
			if k, ok := token.Header["kid"].(string); ok && k != "" {
				kid = k
			}
			key, ok := publicByKid[kid]
			if !ok {
				return nil, fmt.Errorf("unknown key id %q", kid)
			}
			return key, nil
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
	}, jwt.WithIssuer(j.issuer))
	if err != nil {
		return nil, fmt.Errorf("failed to validate %s token: %w", tokenType, err)
	}
	claims, ok := token.Claims.(*CustomClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	if claims.TokenType != tokenType {
		return nil, fmt.Errorf("invalid token type")
	}
	if err := j.checkRevocation(ctx, claims); err != nil {
		return nil, fmt.Errorf("jwt validate %s: %w", tokenType, err)
	}
	return claims, nil
}

func (j *JWTServiceAsymmetric) checkRevocation(ctx context.Context, claims *CustomClaims) error {
	if claims.ID == "" {
		return fmt.Errorf("token missing jti claim")
	}
	if j.revoker == nil {
		return nil
	}
	revoked, err := j.revoker.IsRevoked(ctx, claims.ID)
	if err != nil {
		return fmt.Errorf("revocation check: %w", err)
	}
	if revoked {
		return fmt.Errorf("token revoked")
	}
	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return fmt.Errorf("invalid user_id in claims: %w", err)
	}
	var issuedAt int64
	if claims.IssuedAt != nil {
		issuedAt = claims.IssuedAt.Unix()
	}
	userRevoked, err := j.revoker.IsUserRevoked(ctx, userID, issuedAt)
	if err != nil {
		return fmt.Errorf("user revocation check: %w", err)
	}
	if userRevoked {
		return fmt.Errorf("token revoked")
	}
	return nil
}

// RevokeRefreshToken invalidates the given refresh token via the revocation store.
func (j *JWTServiceAsymmetric) RevokeRefreshToken(ctx context.Context, refreshTokenString string) error {
	claims, err := j.ValidateRefreshToken(ctx, refreshTokenString)
	if err != nil {
		return fmt.Errorf("jwt revoke: %w", err)
	}
	if claims.ID == "" || j.revoker == nil {
		return nil
	}
	ttl := j.refreshTTL
	if claims.ExpiresAt != nil {
		ttl = time.Until(claims.ExpiresAt.Time)
		if ttl <= 0 {
			ttl = j.refreshTTL
		}
	}
	return j.revoker.Revoke(ctx, claims.ID, ttl)
}

// RevokeAccessToken invalidates the given access token. Returns nil if the token is already invalid.
func (j *JWTServiceAsymmetric) RevokeAccessToken(ctx context.Context, accessTokenString string) error {
	claims, err := j.ValidateAccessToken(ctx, accessTokenString)
	if err != nil {
		return nil
	}
	if claims.ID == "" || j.revoker == nil {
		return nil
	}
	ttl := j.accessTTL
	if claims.ExpiresAt != nil {
		ttl = time.Until(claims.ExpiresAt.Time)
		if ttl <= 0 {
			return nil
		}
	}
	return j.revoker.Revoke(ctx, claims.ID, ttl)
}

// RevokeAllForUser invalidates all tokens issued to the user (e.g. after password change).
func (j *JWTServiceAsymmetric) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	if j.revoker == nil {
		return nil
	}
	ttl := j.refreshTTL
	if j.accessTTL > ttl {
		ttl = j.accessTTL
	}
	return j.revoker.RevokeUserTokens(ctx, userID, ttl)
}

// RefreshTokens validates the refresh token, revokes it, and issues a new token pair. Uses UserRoleLookup if set.
func (j *JWTServiceAsymmetric) RefreshTokens(ctx context.Context, refreshTokenString string) (*TokenPair, error) {
	claims, err := j.ValidateRefreshToken(ctx, refreshTokenString)
	if err != nil {
		return nil, fmt.Errorf("failed to validate refresh token: %w", err)
	}
	if j.revoker != nil && claims.ID != "" {
		ttl := j.refreshTTL
		if claims.ExpiresAt != nil {
			ttl = time.Until(claims.ExpiresAt.Time)
			if ttl <= 0 {
				ttl = j.refreshTTL
			}
		}
		if err := j.revoker.Revoke(ctx, claims.ID, ttl); err != nil {
			return nil, fmt.Errorf("failed to revoke old refresh token: %w", err)
		}
	}
	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID in token claims: %w", err)
	}
	email, name, role := claims.Email, claims.FullName, claims.Role
	if fn := j.userRoleLookup.Load(); fn != nil {
		freshEmail, freshName, freshRole, lookupErr := (*fn)(ctx, userID)
		if lookupErr != nil {
			return nil, fmt.Errorf("failed to lookup user role during refresh: %w", lookupErr)
		}
		email, name, role = freshEmail, freshName, freshRole
	}
	return j.GenerateTokenPair(ctx, userID, email, name, role)
}

func signingMethodForKey(priv crypto.PrivateKey) (jwt.SigningMethod, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return jwt.SigningMethodRS256, nil
	case ed25519.PrivateKey:
		return jwt.SigningMethodEdDSA, nil
	case *ecdsa.PrivateKey:
		switch k.Curve.Params().Name {
		case "P-256":
			return jwt.SigningMethodES256, nil
		case "P-384":
			return jwt.SigningMethodES384, nil
		case "P-521":
			return jwt.SigningMethodES512, nil
		default:
			return nil, fmt.Errorf("unsupported ECDSA curve %q", k.Curve.Params().Name)
		}
	default:
		return nil, fmt.Errorf("unsupported key type %T (supported: *rsa.PrivateKey, ed25519.PrivateKey, *ecdsa.PrivateKey)", priv)
	}
}
