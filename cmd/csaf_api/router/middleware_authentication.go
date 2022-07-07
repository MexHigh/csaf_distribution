package router

import (
	"context"
	"net/http"

	"github.com/csaf-poc/csaf_distribution/csaf"
)

type contextKey int

const permissionKey contextKey = 0

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		permissions := make([]csaf.TLPLabel, 0)

		authHeaderContent := r.Header.Get("authorization")
		if authHeaderContent != "" {
			for _, auth := range AuthData {
				if authHeaderContent == "Bearer "+auth.Token {
					permissions = append(permissions, csaf.TLPLabelWhite)
					permissions = append(permissions, auth.AllowedTLPLabels...)
					break
				}
			}
		} else {
			permissions = append(permissions, csaf.TLPLabelWhite)
		}

		// add permissions to request via context
		ctxWithPermissions := context.WithValue(r.Context(), permissionKey, permissions)
		rWithPermissions := r.WithContext(ctxWithPermissions)
		next.ServeHTTP(w, rWithPermissions)
	})
}
