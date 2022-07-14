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
	"errors"
	"net/http"
	"reflect"

	"github.com/csaf-poc/csaf_distribution/csaf"
	"github.com/csaf-poc/csaf_distribution/util"
)

func GetDocumentByJSONMatch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	pathParam := query.Get("path")
	if pathParam == "" {
		reportError(&w, 400, "BAD_REQUEST", "missing required parameter 'path'")
		return
	}
	typeParam := query.Get("type")
	valueParam := query.Get("value")
	if typeParam == "" && valueParam == "" {
		reportError(&w, 400, "BAD_REQUEST", "at least one of 'type' and 'value' is required")
		return
	}
	includeMissingParam := query.Has("include_missing")

	localCollection := *allDocuments // shallow copy of allDocuments
	tlpPerms := getContextVars(r)
	addTLPFilter(&localCollection, tlpPerms)
	if err := addRegularilyUsedFilters(&localCollection, r); err != nil {
		reportError(&w, 400, "BAD_REQUEST", err.Error())
		localCollection.ClearFilterFuncs()
		return
	}

	localCollection.AddFilterFunc(func(doc *csaf.CsafJson) (bool, error) {
		rawDoc, err := structToJSONInterface(*doc)
		if err != nil {
			return false, err
		}
		evaluated, err := util.NewPathEval().Eval(pathParam, rawDoc)
		if err != nil {
			// err != nil if the JSONPath was not found or
			// is otherwise syntactically incorrect
			// TODO maybe differentiate and throw an error
			// if the syntax is not correct?
			if includeMissingParam {
				return true, nil
			}
			return false, err
		}

		if typeParam != "" && valueParam == "" {
			// only type param set
			if isJSONType(evaluated, typeParam) {
				return true, nil
			}
			return false, nil
		} else if typeParam != "" && valueParam != "" {
			// both parameters set
			if isJSONType(evaluated, typeParam) {
				// try to assert *match.Value to string to be able
				// to use the matchByMatchingParameter function.
				// Otherwise, use the reflect.DeepEqual function.
				evalStr, evalOk := evaluated.(string)
				if evalOk {
					m, err := matchByMatching(evalStr, valueParam, r.URL.Query().Get("matching"))
					if err != nil {
						return false, err
					}
					if m {
						return true, nil
					}
					return false, nil
				} else if reflect.DeepEqual(evaluated, valueParam) {
					return true, nil
				}
				return false, nil
			}
			return false, nil
		} else if typeParam == "" && valueParam != "" {
			// only value param set

			// try to assert *match.Value to string to be able
			// to use the matchByMatchingParameter function.
			// Otherwise, use the reflect.DeepEqual function.
			evalStr, evalOk := evaluated.(string)
			if evalOk {
				m, err := matchByMatching(evalStr, valueParam, r.URL.Query().Get("matching"))
				if err != nil {
					return false, err
				}
				if m {
					return true, nil
				}
				return false, nil
			} else if reflect.DeepEqual(evaluated, valueParam) {
				return true, nil
			}
			return false, nil
		}
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

func GetDocumentByJSONMatches(w http.ResponseWriter, r *http.Request) {
	// read request body
	var matchingRequestBody AdvancedMatching
	if err := json.NewDecoder(r.Body).Decode(&matchingRequestBody); err != nil {
		reportError(&w, 400, "BAD_REQUEST", err.Error())
		return
	}

	matchingRequestBody.Provision()
	if err := matchingRequestBody.Check(); err != nil {
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
		rawDoc, err := structToJSONInterface(*doc)
		if err != nil {
			return false, err
		}

		matches := 0
		for _, match := range matchingRequestBody.Matches {
			evaluated, err := util.NewPathEval().Eval(match.Path, rawDoc)
			if err != nil {
				// TODO same optimizations apply as mentioned in the
				// implementation in the GetDocumentByJSONMatch handler
				if match.IncludeMissing {
					matches += 1
				}
				continue
			}
			if match.Type != "" && match.Value == nil {
				// only type param set
				if isJSONType(evaluated, match.Type) {
					matches += 1
				}
			} else if match.Type != "" && match.Value != nil {
				// both parameters set
				if isJSONType(evaluated, match.Type) {
					// try to assert *match.Value to string to be able
					// to use the matchByMatchingParameter function.
					// Otherwise, use the reflect.DeepEqual function.
					evalStr, evalOk := evaluated.(string)
					valueStr, valueOk := (*match.Value).(string)
					if evalOk && valueOk {
						m, err := matchByMatching(evalStr, valueStr, match.Matching)
						if err != nil {
							return false, err
						}
						if m {
							matches += 1
						}
					} else if reflect.DeepEqual(evaluated, *match.Value) {
						matches += 1
					}
				}
			} else if match.Type == "" && match.Value != nil {
				// only value param set

				// try to assert *match.Value to string to be able
				// to use the matchByMatchingParameter function.
				// Otherwise, use the reflect.DeepEqual function.
				evalStr, evalOk := evaluated.(string)
				valueStr, valueOk := (*match.Value).(string)
				if evalOk && valueOk {
					m, err := matchByMatching(evalStr, valueStr, match.Matching)
					if err != nil {
						return false, err
					}
					if m {
						matches += 1
					}
				} else if reflect.DeepEqual(evaluated, *match.Value) {
					matches += 1
				}
			}
		}

		switch matchingRequestBody.Operator {
		case "and":
			if matches == len(matchingRequestBody.Matches) {
				return true, nil
			}
			return false, nil
		case "or":
			if matches > 0 {
				return true, nil
			}
			return false, nil
		default:
			return false, errors.New("matching_operator misconfigured")
		}
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
