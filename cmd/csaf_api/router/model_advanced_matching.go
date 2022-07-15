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
)

type match struct {
	Path           string       `json:"path"`
	Type           string       `json:"type,omitempty"` // default: irrelevant
	Value          *interface{} `json:"value"`
	Matching       string       `json:"matching,omitempty"`        // default: matching_default
	IncludeMissing bool         `json:"include_missing,omitempty"` // default: false (implicit)
}

type advancedMatching struct {
	MatchingDefault string   `json:"matching_default,omitempty"` // default: exact
	Operator        string   `json:"operator,omitempty"`         // (and|or) default: and
	Matches         []*match `json:"matches"`
}

// Provision sets the default values, if not set
func (am *advancedMatching) Provision() {
	if am.Operator == "" {
		am.Operator = "and"
	}
	if am.MatchingDefault == "" {
		am.MatchingDefault = "exact"
	}
	// iterate over matches to set matching
	for _, match := range am.Matches {
		if match.Matching == "" {
			match.Matching = am.MatchingDefault
		}
	}
}

// Check checks if all values are set correctly
// after provision (e.g. if operator is either
// "and" or "or")
func (am *advancedMatching) Check() error {
	// check matching_default
	switch am.MatchingDefault {
	case "exact", "regex", "begins-with", "ends-with", "contains":
	default:
		return fmt.Errorf("matching_default is not (exact|regex|begins-with|ends-with|contains)")
	}

	// check operator
	switch am.Operator {
	case "and", "or":
	default:
		return fmt.Errorf("operator is not (and|or)")
	}

	// check all matching fields in matches
	for i, match := range am.Matches {
		switch match.Matching {
		case "exact", "regex", "begins-with", "ends-with", "contains":
		default:
			return fmt.Errorf("matching in match object %d is not (exact|regex|begins-with|ends-with|contains)", i)
		}
	}

	return nil
}
