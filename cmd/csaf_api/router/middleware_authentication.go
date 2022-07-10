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
			for _, auth := range authData {
				if authHeaderContent == "Bearer "+auth.Token {
					permissions = append(permissions, csaf.TLPLabelWhite)
					permissions = append(permissions, auth.AllowedTLPLabels...)
					break
				}
			}
			if len(permissions) == 0 {
				// no token matched
				// to fulfill requirement IMP-R5, return a "401 Unauthorized" error
				reportError(&w, 401, "AUTH_INVALID", "The specified API token is not known by the server")
				return // do not call next.ServeHTTP to stop middleware chain
			}
		} else {
			// no token provided
			// give permissions to TLP:WHITE (requirement IMP)
			permissions = append(permissions, csaf.TLPLabelWhite)
		}

		// add permissions to request via context
		ctxWithPermissions := context.WithValue(r.Context(), permissionKey, permissions)
		rWithPermissions := r.WithContext(ctxWithPermissions)
		next.ServeHTTP(w, rWithPermissions)

		// IDEA instead of passing the tlp labels down with context, load *allDocuments here
		// and add the tlp filter. As all routes use the same instance of CSAFDocumentCollection
		// the filter will persist until the next filterResetMiddleware hits.
		//
		// This needs refactoring.
	})
}
