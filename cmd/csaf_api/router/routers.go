/*
 * Common Security Advisory Framework (CSAF) 2.0 Distribution API
 *
 * This is the OpenAPI definition of the CSAF 2.0 Distribution API v1.
 *
 * API version: 0.1.4
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package router

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/csaf-poc/csaf_distribution/cmd/csaf_api/config"
	"github.com/csaf-poc/csaf_distribution/csaf"
)

var (
	csafRole     string
	authData     []config.AuthData
	allDocuments *csaf.CSAFDocumentCollection
	docBasePath  string
)

func NewAPI(role string, auth []config.AuthData, docs *csaf.CSAFDocumentCollection, docBase string) *mux.Router {

	csafRole = role
	authData = auth
	allDocuments = docs
	docBasePath = docBase

	router := mux.NewRouter().UseEncodedPath()
	// By default, mux unescapes the whole path
	// BEFORE matching it with a route.
	//
	// We need to use encoded path matchers instead
	// as urls are often used as path parameters.
	// The "https://" scheme would break the path
	// matching otherwise.
	//
	// This requires manual url-unescaping of path
	// parameters in the routes!

	v1Router := router.PathPrefix("/.well-known/csaf/api/v1/").Subrouter()
	// overwrite default handlers to respond with JSON
	v1Router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reportError(&w, 404, "NOT_FOUND", "route not found")
	})
	v1Router.MethodNotAllowedHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reportError(&w, 405, "METHOD_NOT_ALLOWED", "method not allowed")
	})
	v1Router.Use(loggingMiddleware)

	// Meta routes
	v1Router.Methods("GET").Path("/").HandlerFunc(Index).Name("Index")
	v1Router.Methods("GET").Path("/metadata").HandlerFunc(GetMetadata).Name("GetMetadata")
	v1Router.Methods("GET").Path("/role").HandlerFunc(GetRole).Name("GetRole")

	// CSAF routes
	csafV1Router := v1Router.PathPrefix("/csaf-documents").Subrouter()
	csafV1Router.Use(filterResetMiddleware)
	csafV1Router.Use(authMiddleware)
	// macro queries
	csafV1Router.Methods("GET").Path("/by-id/{publisher_namespace}/{tracking_id}").HandlerFunc(GetByID).Name("GetByID")
	csafV1Router.Methods("GET").Path("/by-title/{title}").HandlerFunc(GetByTitle).Name("GetByTitle")
	csafV1Router.Methods("GET").Path("/by-publisher/{publisher_name}").HandlerFunc(GetByPublisher).Name("GetByPublisher")
	csafV1Router.Methods("GET").Path("/by-cve/{cve}").HandlerFunc(GetByCVE).Name("GetByCVE")
	// arbitrary queries
	csafV1Router.Methods("GET").Path("/match-property").HandlerFunc(GetDocumentByJSONMatch).Name("GetDocumentByJSONMatch")
	csafV1Router.Methods("POST").Path("/match-properties").HandlerFunc(GetDocumentByJSONMatches).Name("GetDocumentByJSONMatches")
	// special queries
	csafV1Router.Methods("POST").Path("/from-device-list").HandlerFunc(GetDocumentsByDeviceList).Name("GetDocumentsByDeviceList")
	csafV1Router.Methods("POST").Path("/from-sbom-url").HandlerFunc(GetDocumentsBySBOMUrl).Name("GetDocumentsBySBOMUrl")
	csafV1Router.Methods("POST").Path("/from-sbom-document").HandlerFunc(GetDocumentsBySBOMDocument).Name("GetDocumentsBySBOMDocument")
	csafV1Router.Methods("POST").Path("/from-mud-url").HandlerFunc(GetDocumentsByMUDUrl).Name("GetDocumentsByMUDUrl")
	csafV1Router.Methods("POST").Path("/from-mud-document").HandlerFunc(GetDocumentsByMUDDocument).Name("GetDocumentsByMUDDocument")

	return router
}

func Index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello World!")
}
