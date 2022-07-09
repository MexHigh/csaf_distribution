package router

import (
	"net/http"
	"time"

	"github.com/csaf-poc/csaf_distribution/csaf"
)

const timeLayoutISO8601 = "2006-01-02T15:04:05.000-03:00"

// addBeforeFilter reads the `before` parameter from the request object
// and applies the corresponding filter to the CSAFDocumentCollection
func addBeforeFilter(collection *csaf.CSAFDocumentCollection, r *http.Request) {
	query := r.URL.Query()
	beforePlain := query.Get("before")
	if beforePlain == "" {
		return
	}

	before, err := time.Parse(timeLayoutISO8601, beforePlain)
	if err != nil {
		panic(err)
	}

	collection.AddFilterFunc(func(doc *csaf.CsafJson) bool {
		rDate, err := time.Parse(timeLayoutISO8601, doc.Document.Tracking.InitialReleaseDate)
		if err != nil {
			panic(err)
		}
		if rDate.Before(before) {
			return true
		} else {
			return false
		}
	})
}

// addAfterFilter reads the `after` parameter from the request object
// and applies the corresponding filter to the CSAFDocumentCollection
func addAfterFilter(collection *csaf.CSAFDocumentCollection, r *http.Request) {
	query := r.URL.Query()
	afterPlain := query.Get("after")
	if afterPlain == "" {
		return
	}

	after, err := time.Parse(timeLayoutISO8601, afterPlain)
	if err != nil {
		panic(err)
	}

	collection.AddFilterFunc(func(doc *csaf.CsafJson) bool {
		rDate, err := time.Parse(timeLayoutISO8601, doc.Document.Tracking.InitialReleaseDate)
		if err != nil {
			panic(err)
		}
		if rDate.After(after) {
			return true
		} else {
			return false
		}
	})
}

// addProfileFilter reads the `profile` parameter from the request object
// and applies the corresponding filter to the CSAFDocumentCollection
func addProfileFilter(collection *csaf.CSAFDocumentCollection, r *http.Request) {
	query := r.URL.Query()
	profile := query.Get("profile")
	if profile == "" {
		return
	}

	collection.AddFilterFunc(func(doc *csaf.CsafJson) bool {
		return doc.Document.Category == profile
	})
}

// addTrackingStatusFilter reads the `tracking_status` parameter from the request object
// and applies the corresponding filter to the CSAFDocumentCollection
func addTrackingStatusFilter(collection *csaf.CSAFDocumentCollection, r *http.Request) {
	query := r.URL.Query()
	trackingState := query.Get("tracking_state")
	if trackingState == "" {
		return
	}

	collection.AddFilterFunc(func(doc *csaf.CsafJson) bool {
		return doc.Document.Tracking.Status == csaf.CsafJsonDocumentTrackingStatus(trackingState)
	})
}

// addRegularilyUsedFilters calls addBeforeFilter, addAfterFilter,
// addProfileFilter and addTrackingStatusFilter
func addRegularilyUsedFilters(collection *csaf.CSAFDocumentCollection, r *http.Request) {
	addBeforeFilter(collection, r)
	addAfterFilter(collection, r)
	addProfileFilter(collection, r)
	addTrackingStatusFilter(collection, r)
}
