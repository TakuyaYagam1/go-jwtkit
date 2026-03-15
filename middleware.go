package jwt

import (
	"encoding/json"
	"net/http"
)

// JWTAuth is HTTP middleware that extracts the Bearer token, validates it with svc.ValidateAccessToken,
// stores claims in the request context, and calls next. Returns 401 JSON on missing or invalid token.
func JWTAuth(svc Service, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := ExtractRaw(r)
		if token == "" {
			writeUnauthorized(w)
			return
		}
		claims, err := svc.ValidateAccessToken(r.Context(), token)
		if err != nil {
			writeUnauthorized(w)
			return
		}
		ctx := ClaimsIntoContext(r.Context(), claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "not authenticated"})
}
