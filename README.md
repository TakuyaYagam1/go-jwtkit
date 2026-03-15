# go-jwtkit

JWT issuance, validation, and revocation for access/refresh token pairs.

## Install

```bash
go get github.com/TakuyaYagam1/go-jwtkit
```

```go
import "github.com/TakuyaYagam1/go-jwtkit"
```

## Features

- **HS256** (symmetric): NewJWTService with KeyEntry secrets; key rotation via kid
- **RS256 / EdDSA** (asymmetric): NewJWTServiceAsymmetric with AsymmetricKeyEntry key pairs
- Access and refresh tokens with configurable TTLs and issuer
- **RevocationStore**: blacklist JTIs and user-level revocation (e.g. RedisRevocationStore)
- **UserRoleLookup**: refresh email/name/role when issuing new tokens from refresh token
- **HTTP**: JWTAuth middleware; ExtractRaw, ExtractRawFromCookie; ClaimsFromContext, UserIDFromContext, RoleFromContext

## Example

```go
svc, err := jwt.NewJWTService(
    []jwt.KeyEntry{{Kid: "0", Secret: accessSecret}},
    []jwt.KeyEntry{{Kid: "0", Secret: refreshSecret}},
    time.Hour, 24*time.Hour, "my-app", redisRevoker, userRoleLookup,
)
pair, _ := svc.GenerateTokenPair(ctx, userID, email, name, role)

mux := http.NewServeMux()
mux.Handle("/api/", jwt.JWTAuth(svc, apiHandler))
```

In handlers after JWTAuth:

```go
userID, ok := jwt.UserIDFromContext(r.Context())
claims, ok := jwt.ClaimsFromContext(r.Context())
```

## API

| Symbol | Description |
|--------|-------------|
| Service | Interface: GenerateTokenPair, ValidateAccessToken, ValidateRefreshToken, RefreshTokens, Revoke*, RevokeAllForUser |
| JWTService | HS256 implementation; NewJWTService |
| JWTServiceAsymmetric | RS256/EdDSA implementation; NewJWTServiceAsymmetric, AsymmetricKeyEntry |
| CustomClaims | UserID, Email, FullName, Role, TokenType, RegisteredClaims |
| TokenPair | AccessToken, RefreshToken, AccessExpiresAt, RefreshExpiresAt |
| KeyEntry | Kid, Secret (symmetric) |
| RevocationStore | Revoke, IsRevoked, RevokeUserTokens, IsUserRevoked; RedisRevocationStore |
| JWTAuth(svc, next) | HTTP middleware: Bearer validation, claims in context; 401 on failure |
| ExtractRaw(r), ExtractRawFromCookie(r, name) | Raw token from header or cookie |
| ClaimsIntoContext, ClaimsFromContext, UserIDFromContext, RoleFromContext | Context helpers |
