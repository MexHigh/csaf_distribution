package router

import (
	"net/http"
)

// filterResetMiddleware removes all previously set filter functions
// in the global CSAFDocumentCollection instance. They might be still set
// due to filtering errors.
func filterResetMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allDocuments.ClearFilterFuncs()
		next.ServeHTTP(w, r)
	})
}
