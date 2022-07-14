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
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/csaf-poc/csaf_distribution/csaf"
)

type Device csaf.FullProductNameTProductIdentificationHelper

func GetDocumentsByDeviceList(w http.ResponseWriter, r *http.Request) {
	// read request body
	var deviceListRequestBody []Device
	if err := json.NewDecoder(r.Body).Decode(&deviceListRequestBody); err != nil {
		reportError(&w, 400, "BAD_REQUEST", err.Error())
		return
	}

	localCollection := *allDocuments // shallow copy of allDocuments
	tlpPerms := getContextVars(r)
	addTLPFilter(&localCollection, tlpPerms)
	/*if err := addRegularilyUsedFilters(&localCollection, r); err != nil {
		reportError(&w, 400, "BAD_REQUEST", err.Error())
		localCollection.ClearFilterFuncs()
		return
	}*/ // they are not needed in this route

	localCollection.AddFilterFunc(func(doc *csaf.CsafJson) (bool, error) {
		products := findAllProductObjects(doc)
		for _, product := range products {
			// match the product with one of the searched products
			// in the request body
			matched := false
			for _, searchedProduct := range deviceListRequestBody {
				if anyIdentificationHelperMatches( // TODO implement
					Device(*product.ProductIdentificationHelper),
					searchedProduct,
				) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}

			vulnObjects := findVulnObjectsWithProduct(doc, product)
			// convert []csaf.CsafJsonVulnerabilitiesElem to map[int]csaf.CsafJsonVulnerabilitiesElem
			// for easier deletion of items
			vulnObjectsMap := make(map[int]csaf.CsafJsonVulnerabilitiesElem, 0)
			for index, vulnObj := range vulnObjects {
				vulnObjectsMap[index] = vulnObj
			}

			keysToRemove := make([]int, 0)
			for key, vulnObj := range vulnObjectsMap {
				// TODO
				fmt.Println(key, vulnObj)
			}

			// delete the keys
			for _, key := range keysToRemove {
				delete(vulnObjectsMap, key)
			}

			if len(vulnObjectsMap) > 0 {
				// at least one matched vuln_objects left after filtering
				// --> add document
				return true, nil
			}
		}
		// for loop did not return --> no document matched
		// --> don't add to response
		return false, nil
	})

	filtered, err := localCollection.StartFiltering(true)
	if err != nil {
		reportError(&w, 400, "BAD_REQUEST", err.Error())
		localCollection.ClearFilterFuncs()
		return
	}

	withHashes, withSignatures := getWithParameters(r)
	reportSuccess(&w, filtered, withHashes, withSignatures)
}

func GetDocumentsByMUDDocument(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
}

func GetDocumentsByMUDUrl(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
}

func GetDocumentsBySBOMDocument(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
}

func GetDocumentsBySBOMUrl(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
}
