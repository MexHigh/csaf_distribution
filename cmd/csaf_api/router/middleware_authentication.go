package router

import (
	"context"
	"net/http"

	"github.com/csaf-poc/csaf_distribution/csaf"
)

var allowedTokens = []string{
	"Bearer abc123",
	"Bearer def456",
}

type contextKey int

const permissionKey contextKey = 0

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		permissions := make([]csaf.TLPLabel, 0)

		auth := r.Header.Get("authorization")
		if auth == "" {
			// no auth data
			permissions = append(permissions, csaf.TLPLabelWhite)
		} else {
			authenticated := false
			for _, token := range allowedTokens {
				if token == auth {
					authenticated = true
					break
				}
			}
			if authenticated {
				permissions = append(permissions, csaf.TLPLabelWhite, csaf.TLPLabelGreen, csaf.TLPLabelAmber, csaf.TLPLabelRed)
			}
		}

		// add permissions to request via context
		ctxWithPermissions := context.WithValue(r.Context(), permissionKey, permissions)
		rWithPermissions := r.WithContext(ctxWithPermissions)
		next.ServeHTTP(w, rWithPermissions)
	})
}
