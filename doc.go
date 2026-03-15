// Package jwt provides JWT issuance, validation, and revocation for access/refresh token pairs.
//
// HS256 (symmetric): use NewJWTService with KeyEntry secrets; configurable issuer and TTLs,
// key rotation via kid, and an optional RevocationStore (e.g. RedisRevocationStore).
// RS256/EdDSA (asymmetric): use NewJWTServiceAsymmetric with AsymmetricKeyEntry key pairs.
// UserRoleLookup can refresh email/name/role when issuing new tokens from a refresh token.
//
// HTTP integration: JWTAuth middleware validates the Bearer token and stores claims in context;
// use ClaimsFromContext, UserIDFromContext, RoleFromContext in handlers. ExtractRaw reads the
// token from Authorization header; ExtractRawFromCookie from a cookie.
package jwt
