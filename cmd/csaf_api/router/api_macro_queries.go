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
	"fmt"
	"net/http"
	"net/url"

	"github.com/gorilla/mux"

	"github.com/csaf-poc/csaf_distribution/csaf"
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

	localCollection := *allDocuments // shallow copy of allDocuments
	tlpPerms := getContextVars(r)
	addTLPFilter(&localCollection, tlpPerms)

	localCollection.AddFilterFunc(func(doc *csaf.CsafJson) (bool, error) {
		return doc.Document.Publisher.Namespace == namespace && doc.Document.Tracking.Id == trackingID, nil
	})

	filtered, err := localCollection.StartFiltering(true)
	if err != nil {
		reportError(&w, 400, "BAD_REQUEST", err.Error())
		localCollection.ClearFilterFuncs()
		return
	}

	reportSuccess(&w, filtered)
}

func GetByPublisher(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	publisherNameEncoded, ok := vars["publisher_name"]
	if !ok {
		reportError(&w, 400, "BAD_REQUEST", "Missing publisher_name parameter")
		return
	}
	publisherName, err := url.PathUnescape(publisherNameEncoded)
	if err != nil {
		reportError(&w, 500, "UNKOWN", "Unable to URL-unescape publisher_name parameter")
		return
	}

	localCollection := *allDocuments // shallow copy of allDocuments
	tlpPerms := getContextVars(r)
	addTLPFilter(&localCollection, tlpPerms)
	if err := addRegularilyUsedFilters(&localCollection, r); err != nil {
		reportError(&w, 400, "BAD_REQUEST", err.Error())
		localCollection.ClearFilterFuncs()
		return
	}

	localCollection.AddFilterFunc(func(doc *csaf.CsafJson) (bool, error) {
		m, err := matchByMatchingParameter(doc.Document.Publisher.Name, publisherName, r)
		//fmt.Printf("Matching '%s' with '%s': %v\n", publisherName, doc.Document.Publisher.Name, m)
		return m, err
	})

	query := r.URL.Query()

	if publisherNamespace := query.Get("publisher_namespace"); publisherNamespace != "" {
		localCollection.AddFilterFunc(func(doc *csaf.CsafJson) (bool, error) {
			fmt.Println(doc.Document.Publisher.Namespace, publisherNamespace)
			return doc.Document.Publisher.Namespace == publisherNamespace, nil
		})
	}

	if publisherCategory := query.Get("publisher_category"); publisherCategory != "" {
		localCollection.AddFilterFunc(func(doc *csaf.CsafJson) (bool, error) {
			return doc.Document.Publisher.Category == csaf.PublisherCategory(publisherCategory), nil
		})
	}

	filtered, err := localCollection.StartFiltering(true)
	if err != nil {
		reportError(&w, 400, "BAD_REQUEST", err.Error())
		localCollection.ClearFilterFuncs()
		return
	}

	reportSuccess(&w, filtered)
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

	localCollection := *allDocuments // shallow copy of allDocuments
	tlpPerms := getContextVars(r)
	addTLPFilter(&localCollection, tlpPerms)
	if err := addRegularilyUsedFilters(&localCollection, r); err != nil {
		reportError(&w, 400, "BAD_REQUEST", err.Error())
		localCollection.ClearFilterFuncs()
		return
	}

	localCollection.AddFilterFunc(func(doc *csaf.CsafJson) (bool, error) {
		return matchByMatchingParameter(doc.Document.Title, title, r)
	})

	filtered, err := localCollection.StartFiltering(true)
	if err != nil {
		reportError(&w, 400, "BAD_REQUEST", err.Error())
		localCollection.ClearFilterFuncs()
		return
	}

	reportSuccess(&w, filtered)
}
