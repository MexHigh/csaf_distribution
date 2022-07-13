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
// wheather they are set.
func getWithParameters(r *http.Request) (withHashes, withSignature bool) {
	query := r.URL.Query()
	// no need to check values, as the parameters are expected to be bool
	return query.Has("with_hashes"), query.Has("with_signature")
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

// matchByMatchingParameter matches two strings depending on the method set in "?matching=".
// If it is not set or empty, exact matching is performed.
//
// Possible values are "exact", "regex", "begins-with", "ends-with" and "contains".
// If other values are set, an error is returned.
//
// Deprecated: use matchByMatching instead
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

func reportSuccess(w *http.ResponseWriter, documents []csaf.CSAFDocumentWrapper, withHash, withSignature bool) {
	obj := CSAFDocumentResponse{
		GenericResponse: GenericResponse{
			Error: nil,
		},
		DocumentsFound: len(documents),
		Documents:      make([]CSAFDocumentResponseDocuments, 0),
	}

	for _, doc := range documents {
		tDoc := doc // needed to prevent race conditions !!! (sometimes, documents are added twice)
		toAdd := CSAFDocumentResponseDocuments{
			Content: tDoc.Document,
		}
		if withHash {
			toAdd.Hashes = tDoc.Hashes
		}
		if withSignature {
			toAdd.Signature = tDoc.Signature
		}
		obj.Documents = append(obj.Documents, toAdd)
	}

	v, err := json.Marshal(obj)
	if err != nil {
		reportError(w, 500, "SERVER_ERROR", err.Error())
		return
	}

	(*w).Header().Set("Content-Type", "application/json; charset=UTF-8")
	(*w).WriteHeader(http.StatusOK)
	(*w).Write(v)
}
