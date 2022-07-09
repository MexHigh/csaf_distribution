/*
 * Common Security Advisory Framework (CSAF) 2.0 Distribution API
 *
 * This is the OpenAPI definition of the CSAF 2.0 Distribution API v1 designed to be implemented in (trusted) providers
 *
 * API version: 0.1.4
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package router

import (
	"net/http"
	"net/url"

	"github.com/csaf-poc/csaf_distribution/csaf"
	"github.com/gorilla/mux"
)

func GetByCVE(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
}

func GetByID(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	namespaceEncoded, ok := vars["publisher_namespace"]
	if !ok {
		reportError(&w, 400, "BAD_REQUEST", "Missing namespace parameter")
		return
	}
	namespace, err := url.PathUnescape(namespaceEncoded)
	if err != nil {
		reportError(&w, 500, "UNKOWN", "Unable to URL-unescape namespace parameter")
		return
	}
	trackingID, ok := vars["tracking_id"]
	if !ok {
		reportError(&w, 400, "BAD_REQUEST", "Missing tracking ID parameter")
		return
	}

	localCollection := *allDocuments // real copy of allDocuments
	tlpPerms := getContextVars(r)
	addTLPFilter(&localCollection, tlpPerms)
	localCollection.AddFilterFunc(func(doc *csaf.CsafJson) (bool, error) {
		return doc.Document.Publisher.Namespace == namespace && doc.Document.Tracking.Id == trackingID, nil
	})

	filtered, err := localCollection.StartFiltering(true)
	if err != nil {
		reportError(&w, 400, "BAD_REQUEST", err.Error())
		return
	}

	reportSuccess(&w, filtered)
}

func GetByPublisher(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
}

func GetByTitle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	titleEncoded, ok := vars["title"]
	if !ok {
		reportError(&w, 400, "BAD_REQUEST", "Missing title parameter")
		return
	}
	title, err := url.PathUnescape(titleEncoded)
	if err != nil {
		reportError(&w, 500, "UNKOWN", "Unable to URL-unescape title parameter")
		return
	}

	localCollection := *allDocuments // real copy of allDocuments
	tlpPerms := getContextVars(r)
	addTLPFilter(&localCollection, tlpPerms)
	addRegularilyUsedFilters(&localCollection, r)

	localCollection.AddFilterFunc(func(doc *csaf.CsafJson) (bool, error) {
		return matchByMatchingParameter(doc.Document.Title, title, r)
	})

	filtered, err := localCollection.StartFiltering(true)
	if err != nil {
		reportError(&w, 400, "BAD_REQUEST", err.Error())
		return
	}

	reportSuccess(&w, filtered)
}
