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
	"strings"

	"github.com/csaf-poc/csaf_distribution/csaf"
)

type device csaf.FullProductNameTProductIdentificationHelper

func getDocumentsByDeviceList(w http.ResponseWriter, r *http.Request) {
	// read request body
	var deviceListRequestBody []device
	if err := json.NewDecoder(r.Body).Decode(&deviceListRequestBody); err != nil {
		reportError(&w, 400, "BAD_REQUEST", err.Error())
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

	query := r.URL.Query()
	productStatusParam := query.Get("product_status")
	cvssv3Param := query.Get("cvssv3")
	cvssv3ParamSplit := strings.Split(cvssv3Param, ",")
	cvssv2Param := query.Get("cvssv2")
	cvssv2ParamSplit := strings.Split(cvssv2Param, ",")
	remediationCategoryParam := query.Get("remediation_category")

	localCollection.AddFilterFunc(func(doc *csaf.CsafJson) (bool, error) {
		products := findAllProductObjects(doc)
		for _, product := range products {
			if product.ProductIdentificationHelper == nil {
				// no product identification helper --> skip
				continue
			}
			// match the product with one of the searched products
			// in the request body
			matched := false
			for _, searchedProduct := range deviceListRequestBody {
				if anyIdentificationHelperMatches(
					device(*product.ProductIdentificationHelper),
					searchedProduct,
				) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}

			// implements product_status filter
			var vulnObjects []csaf.CsafJsonVulnerabilitiesElem
			if productStatusParam == "" {
				// product_status not set
				vulnObjects = findVulnObjectsWithProduct(doc, product)
			} else {
				// product_status set
				vulnObjects = findVulnObjectsWithProduct(doc, product, productStatusParam)
			}

			// convert []csaf.CsafJsonVulnerabilitiesElem to map[int]csaf.CsafJsonVulnerabilitiesElem
			// for easier deletion of items
			vulnObjectsMap := make(map[int]csaf.CsafJsonVulnerabilitiesElem, 0)
			for index, vulnObj := range vulnObjects {
				vulnObjectsMap[index] = vulnObj
			}

			keysToRemove := make([]int, 0)
			for key, vulnObj := range vulnObjectsMap {
				vulnObjectMatches := true
				// Must default true! Otherwise, when no filter parameters
				// are set, the document will not be included, although the
				// device was matched.

				// check for cvss scores if filter parameter is set
				if cvssv3Param != "" || cvssv2Param != "" {
					// at least one of the params was set

					vulnObjectMatches = false
					// this only will be true if any css score matches

					if vulnObj.Scores == nil || len(vulnObj.Scores) == 0 {
						vulnObjectMatches = true
						// justification: see section 3.2.3 of bachelors thesis
						continue
					}
					anyMatch := false
					for _, score := range vulnObj.Scores {
						if cvssv3Param != "" {
							str := fmt.Sprintf("%f", *score.CvssV3.BaseScore)
							match, err := matchCVSSScore(str, cvssv3ParamSplit...)
							if err != nil {
								// on error, stop and report
								return false, err
							}
							if match {
								// cvssv3 matched
								anyMatch = true
								break
							}
						}
						if cvssv2Param != "" {
							str := fmt.Sprintf("%f", *score.CvssV2.BaseScore)
							match, err := matchCVSSScore(str, cvssv2ParamSplit...)
							if err != nil {
								// on error, stop and report
								return false, err
							}
							if match {
								// cvssv2 matched
								anyMatch = true
								break
							}
						}
					}
					if anyMatch {
						vulnObjectMatches = true
					}
				}

				// check for remediation_category parameter
				if remediationCategoryParam != "" {
					if !atLeastOneRemediationExists(&product, &vulnObj, remediationCategoryParam) {
						vulnObjectMatches = false
					}
				}

				if !vulnObjectMatches {
					keysToRemove = append(keysToRemove, key)
				}
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
