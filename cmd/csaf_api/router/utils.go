package router

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/csaf-poc/csaf_distribution/csaf"
)

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

// matchByMatchingParameter matches two strings depending on the method set in "?matching=".
// If it is not set or empty, exact matching is performed.
//
// Possible values are "exact", "regex", "begins-with", "ends-with" and "contains".
// If other values are set, an error is returned.
func matchByMatchingParameter(searchString, toMatchString string, r *http.Request) (bool, error) {
	query := r.URL.Query()
	matching := query.Get("matching")
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

func reportError(w *http.ResponseWriter, statusCode int, errcode, errmsg string) {
	obj := GenericResponse{
		Error: &ModelError{
			Errcode: errcode,
			Errmsg:  errmsg,
		},
	}

	v, err := json.Marshal(obj)
	if err != nil {
		panic(err)
	}

	(*w).Header().Set("Content-Type", "application/json; charset=UTF-8")
	(*w).WriteHeader(statusCode)
	(*w).Write(v)
}

func reportSuccess(w *http.ResponseWriter, documents []csaf.CsafJson) {
	obj := CsafDocumentResponse{
		GenericResponse: GenericResponse{
			Error: nil,
		},
		DocumentsFound: len(documents),
		Documents:      make([]CsafDocumentResponseDocuments, 0),
	}

	for _, doc := range documents {
		tDoc := doc // needed to prevent race conditions !!! (sometimes, documents are added twice)
		obj.Documents = append(obj.Documents, CsafDocumentResponseDocuments{
			Content: &tDoc,
		})
	}

	v, err := json.MarshalIndent(obj, "", "    ")
	if err != nil {
		reportError(w, 500, "SERVER_ERROR", err.Error())
		return
	}

	(*w).Header().Set("Content-Type", "application/json; charset=UTF-8")
	(*w).WriteHeader(http.StatusOK)
	(*w).Write(v)
}
