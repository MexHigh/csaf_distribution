package router

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"strings"

	"github.com/PaesslerAG/gval"
	"github.com/csaf-poc/csaf_distribution/csaf"
)

// structToJSONInterface converts a filled struct back to it's
// byte representation and then unmarshals it back to the
// interface{} type. This is useful when some kind of interface{}
// evaluation of a struct is required by a dependency or other function.
func structToJSONInterface(s interface{}) (interface{}, error) {
	data, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	var dataIf interface{}
	err = json.Unmarshal(data, &dataIf)
	if err != nil {
		return nil, err
	}
	return dataIf, nil
}

// isJSONType returns whether v is of JSON type t. It uses the reflect
// package to determine the Go-type of v and maps it to the types used
// for unmarshalling JSON into a Go-struct. This way, the original JSON
// type can be detected.
func isJSONType(v interface{}, t string) bool {
	if v == nil {
		return false
	}
	switch t {
	case "string":
		if reflect.TypeOf(v).String() == "string" {
			return true
		}
	case "number":
		if reflect.TypeOf(v).String() == "float64" {
			return true
		}
	case "object":
		if reflect.TypeOf(v).String() == "map[string]interface {}" {
			return true
		}
	case "array":
		if reflect.TypeOf(v).String() == "[]interface {}" {
			return true
		}
	case "boolean":
		if reflect.TypeOf(v).String() == "bool" {
			return true
		}
	default:
		return false
	}
	return false
}

// getContextVars is a helper function that extracts
// all context variables set by middleware. Currently,
// it returns:
//
// TLP labels, the user authenticated himself for ([]csaf.TLPLabel)
func getContextVars(r *http.Request) []csaf.TLPLabel {
	// get permissions from auth middleware
	perms := r.Context().Value(permissionKey).([]csaf.TLPLabel)
	return perms
}

// getWithParameters reads the "?with_*" parameters and returns
// whether they are set.
func getWithParameters(r *http.Request) (withHashes, withSignature bool) {
	query := r.URL.Query()
	// no need to check values, as the parameters are expected to be bool
	return query.Has("with_hashes"), query.Has("with_signature")
}

// addTLPFilter adds a TLP filter to a CSAFDocumentCollection without executing
// it directly. Call CSAFDocumentCollection.StartFiltering() to execute all
// filters.
//
// The filter matches all documents with the TLP-Labels specified in tlpPerms.
// If len(tlpPerms) == 0, all document will be filtered out!
func addTLPFilter(collection *csaf.CSAFDocumentCollection, tlpPerms []csaf.TLPLabel) {
	collection.AddFilterFunc(func(doc *csaf.CsafJson) (bool, error) {
		allowed := false
		for _, label := range tlpPerms {
			if doc.Document.Distribution.Tlp.Label == label {
				allowed = true
				break
			}
		}
		return allowed, nil
	})
}

var gvalBaseArithLang = gval.NewLanguage(gval.Base(), gval.Arithmetic())

// matchCVSSScore uses gval Base+Arithmetic language to test if cvss scores
// match. It concatenates the score from a CSAF document ("score")
// with each item in expressions usually set as query paramter.
// Every expression must match. If len(expressions) is 0, (true, nil)
// is returned.
//
// Example:
//
// score = "8.0";
// expressions = [">7", "<9"]
//
// matchCVSSScore(score, expressions...) = (true, nil)
func matchCVSSScore(score string, expressions ...string) (bool, error) {
	allMatched := true
	for _, expression := range expressions {
		eval, err := gvalBaseArithLang.NewEvaluable(score + expression)
		if err != nil {
			return false, err
		}
		val, err := eval.EvalBool(context.Background(), nil)
		if err != nil {
			return false, err
		}
		if !val {
			allMatched = false
			break
		}
	}
	return allMatched, nil
}

// matchByMatching works exactly like matchByMatchingParameter, but instead of
// passing it a http.Request object, it takes the matching string directly.
// This can be useful when the matching parameter is not included in the URL
// query but in the request body, for example.
func matchByMatching(searchString, toMatchString, matching string) (bool, error) {
	if matching == "" {
		// if not set, matching is exact
		return searchString == toMatchString, nil
	}

	switch matching {
	case "exact":
		return searchString == toMatchString, nil
	case "regex":
		return regexp.MatchString(toMatchString, searchString)
	case "begins-with":
		return strings.HasPrefix(searchString, toMatchString), nil
	case "ends-with":
		return strings.HasSuffix(searchString, toMatchString), nil
	case "contains":
		return strings.Contains(searchString, toMatchString), nil
	default:
		return false, fmt.Errorf("matching parameter value %s is unknown", matching)
	}
}

// findAllProductObjects seaches for all FullProductNameT objects
// inside the /product_tree property
func findAllProductObjects(doc *csaf.CsafJson) []csaf.FullProductNameT {
	products := make([]csaf.FullProductNameT, 0)

	// read from /propduct_tree/full_product_trees
	products = append(products, doc.ProductTree.FullProductNames...)

	// read from /product_tree/relationships
	for _, rel := range doc.ProductTree.Relationships {
		products = append(products, rel.FullProductName)
	}

	// read from /product_tree/branches
	for _, entryBranch := range doc.ProductTree.Branches {
		products = append(products, recurseBranches(&entryBranch)...)
	}

	// No need to read from /product_tree/product_groups
	// as they do not yield product_ids

	return products
}

// recurseBranches recursively finds all FullProductNameT objects in a
// branch
func recurseBranches(currentBranch *csaf.Branch) []csaf.FullProductNameT {
	if currentBranch.Branches == nil {
		return []csaf.FullProductNameT{currentBranch.Product}
	}
	branches := make([]csaf.FullProductNameT, 0)
	for _, branch := range *currentBranch.Branches {
		branches = append(branches, recurseBranches(&branch)...)
	}
	return branches
}

// findVulnObjectsWithProduct returns all vuln objectes that contain the product specified.
// Additionaly, you can specify productStatus, for with of them to filter. If no productStatus
// is specified, all productStatuses are conducted.
func findVulnObjectsWithProduct(doc *csaf.CsafJson, fpnt csaf.FullProductNameT, productStatus ...string) []csaf.CsafJsonVulnerabilitiesElem {
	if len(productStatus) == 0 {
		productStatus = []string{
			"first_affected",
			"first_fixed",
			"fixed",
			"known_affected",
			"known_not_affected",
			"last_affected",
			"recommended",
			"under_investigation",
		}
	}

	result := make([]csaf.CsafJsonVulnerabilitiesElem, 0)

	for _, vulnObj := range doc.Vulnerabilities {
		// first_affected
		if c, _ := stringSliceContains(productStatus, "first_affected"); c {
			if vulnObj.ProductStatus.FirstAffected != nil {
				for _, fa := range *vulnObj.ProductStatus.FirstAffected {
					if fa == fpnt.ProductId {
						result = append(result, vulnObj)
					}
				}
			}
		}
		// first_fixed
		if c, _ := stringSliceContains(productStatus, "first_fixed"); c {
			if vulnObj.ProductStatus.FirstFixed != nil {
				for _, fa := range *vulnObj.ProductStatus.FirstFixed {
					if fa == fpnt.ProductId {
						result = append(result, vulnObj)
					}
				}
			}
		}
		// fixed
		if c, _ := stringSliceContains(productStatus, "fixed"); c {
			if vulnObj.ProductStatus.Fixed != nil {
				for _, fa := range *vulnObj.ProductStatus.Fixed {
					if fa == fpnt.ProductId {
						result = append(result, vulnObj)
					}
				}
			}
		}
		// known_affected
		if c, _ := stringSliceContains(productStatus, "known_affected"); c {
			if vulnObj.ProductStatus.KnownAffected != nil {
				for _, fa := range *vulnObj.ProductStatus.KnownAffected {
					if fa == fpnt.ProductId {
						result = append(result, vulnObj)
					}
				}
			}
		}
		// known_not_affected
		if c, _ := stringSliceContains(productStatus, "known_not_affected"); c {
			if vulnObj.ProductStatus.KnownNotAffected != nil {
				for _, fa := range *vulnObj.ProductStatus.KnownNotAffected {
					if fa == fpnt.ProductId {
						result = append(result, vulnObj)
					}
				}
			}
		}
		// last_affected
		if c, _ := stringSliceContains(productStatus, "last_affected"); c {
			if vulnObj.ProductStatus.LastAffected != nil {
				for _, fa := range *vulnObj.ProductStatus.LastAffected {
					if fa == fpnt.ProductId {
						result = append(result, vulnObj)
					}
				}
			}
		}
		// recommended
		if c, _ := stringSliceContains(productStatus, "recommended"); c {
			if vulnObj.ProductStatus.Recommended != nil {
				for _, fa := range *vulnObj.ProductStatus.Recommended {
					if fa == fpnt.ProductId {
						result = append(result, vulnObj)
					}
				}
			}
		}
		// under_investigation
		if c, _ := stringSliceContains(productStatus, "under_investigation"); c {
			if vulnObj.ProductStatus.UnderInvestigation != nil {
				for _, fa := range *vulnObj.ProductStatus.UnderInvestigation {
					if fa == fpnt.ProductId {
						result = append(result, vulnObj)
					}
				}
			}
		}
	}
	return result
}

// anyIdentificationHelperMatches tries to compare two Device instances
// on every property
func anyIdentificationHelperMatches(refDevice, toMatchDevice device) bool {
	if (refDevice.Cpe != nil && toMatchDevice.Cpe != nil) && (*refDevice.Cpe == *toMatchDevice.Cpe) {
		// TODO use a better approach to compare CPE
		return true
	}
	if refDevice.Hashes != nil && toMatchDevice.Hashes != nil {
		// I found no way to make this comparison easier
		// as it is nested relatively deep
		for _, rHashes := range refDevice.Hashes {
			for _, tHashes := range toMatchDevice.Hashes {
				for _, rHashesHash := range rHashes.FileHashes {
					for _, tHashesHash := range tHashes.FileHashes {
						if rHashes.Filename == tHashes.Filename && rHashesHash.Algorithm == tHashesHash.Algorithm && rHashesHash.Value == tHashesHash.Value {
							return true
						}
					}
				}
			}
		}
		return false
	}
	if (refDevice.ModelNumbers != nil && toMatchDevice.ModelNumbers != nil) && anyMatches(refDevice.ModelNumbers, toMatchDevice.ModelNumbers) {
		return true
	}
	if (refDevice.Purl != nil && toMatchDevice.Purl != nil) && *refDevice.Purl == *toMatchDevice.Purl {
		return true
	}
	if (refDevice.SbomUrls != nil && toMatchDevice.SbomUrls != nil) && anyMatches(refDevice.SbomUrls, toMatchDevice.SbomUrls) {
		return true
	}
	if (refDevice.SerialNumbers != nil && toMatchDevice.SerialNumbers != nil) && anyMatches(refDevice.SerialNumbers, toMatchDevice.SerialNumbers) {
		return true
	}
	if (refDevice.Skus != nil && toMatchDevice.Skus != nil) && anyMatches(refDevice.Skus, toMatchDevice.Skus) {
		return true
	}
	return false
}

// atLeastOneRemediationExists checks if at least one remediation object exists in a vulnerability
// object. You can specify remediation categories (see CSAF 2.0 section 3.2.3.12.1) for which to
// search specifically. If no categories are specified, all remediation categories count.
func atLeastOneRemediationExists(vulnObj *csaf.CsafJsonVulnerabilitiesElem, categories ...string) bool {
	if len(categories) == 0 {
		categories = []string{
			"mitigation",
			"no_fix_planned",
			"none_available",
			"vendor_fix",
			"workaround",
		}
	}
	if vulnObj.Remediations == nil || len(vulnObj.Remediations) == 0 {
		return false
	}
	for _, remediation := range vulnObj.Remediations {
		if c, _ := stringSliceContains(categories, string(remediation.Category)); c {
			return true
		}
	}
	return false
}

// stringSliceContains checks whether a string (search) is
// contained within a string slice (target). The index, where
// the searched string was found is also returned as a second
// return value.
func stringSliceContains(target []string, search string) (bool, int) {
	for i, t := range target {
		if t == search {
			return true, i
		}
	}
	return false, -1
}

// anyMatches checks, if two string slices contain
// at least one common value. The index of these values
// is irrelevant, meaning that s1[10] can also match
// s2[45].
func anyMatches(s1, s2 []string) bool {
	for _, c1 := range s1 {
		for _, c2 := range s2 {
			if c1 == c2 {
				return true
			}
		}
	}
	return false
}
