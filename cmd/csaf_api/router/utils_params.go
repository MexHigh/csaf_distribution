package router

import (
	"fmt"
	"net/http"
	"time"

	"github.com/csaf-poc/csaf_distribution/csaf"
)

const timeLayout = time.RFC3339

// addBeforeFilter reads the `before` parameter from the request object
// and applies the corresponding filter to the CSAFDocumentCollection
func addBeforeFilter(collection *csaf.CSAFDocumentCollection, r *http.Request) error {
	query := r.URL.Query()
	beforePlain := query.Get("before")
	if beforePlain == "" {
		return nil
	}

	before, err := time.Parse(timeLayout, beforePlain)
	if err != nil {
		return err
	}

	collection.AddFilterFunc(func(doc *csaf.CsafJson) (bool, error) {
		rDate, err := time.Parse(timeLayout, doc.Document.Tracking.InitialReleaseDate)
		if err != nil {
			return false, err
		}
		if rDate.Before(before) {
			return true, nil
		} else {
			return false, nil
		}
	})

	return nil
}

// addAfterFilter reads the `after` parameter from the request object
// and applies the corresponding filter to the CSAFDocumentCollection
func addAfterFilter(collection *csaf.CSAFDocumentCollection, r *http.Request) error {
	query := r.URL.Query()
	afterPlain := query.Get("after")
	if afterPlain == "" {
		return nil
	}

	after, err := time.Parse(timeLayout, afterPlain)
	if err != nil {
		return err
	}

	collection.AddFilterFunc(func(doc *csaf.CsafJson) (bool, error) {
		rDate, err := time.Parse(timeLayout, doc.Document.Tracking.InitialReleaseDate)
		if err != nil {
			return false, err
		}
		if rDate.After(after) {
			return true, nil
		} else {
			return false, nil
		}
	})

	return nil
}

// addProfileFilter reads the `profile` parameter from the request object
// and applies the corresponding filter to the CSAFDocumentCollection
func addProfileFilter(collection *csaf.CSAFDocumentCollection, r *http.Request) error {
	query := r.URL.Query()
	profile := query.Get("profile")
	if profile == "" {
		return nil
	}

	collection.AddFilterFunc(func(doc *csaf.CsafJson) (bool, error) {
		return doc.Document.Category == profile, nil
	})

	return nil
}

// addTrackingStatusFilter reads the `tracking_status` parameter from the request object
// and applies the corresponding filter to the CSAFDocumentCollection
func addTrackingStatusFilter(collection *csaf.CSAFDocumentCollection, r *http.Request) error {
	query := r.URL.Query()
	trackingStatus := query.Get("tracking_status")
	if trackingStatus == "" {
		return nil
	}
	switch trackingStatus {
	case "draft", "final", "interim":
	default:
		return fmt.Errorf("tracking status %s is not supported", trackingStatus)
	}

	collection.AddFilterFunc(func(doc *csaf.CsafJson) (bool, error) {
		return doc.Document.Tracking.Status == csaf.CsafJsonDocumentTrackingStatus(trackingStatus), nil
	})

	return nil
}

// addRegularilyUsedFilters calls addBeforeFilter, addAfterFilter,
// addProfileFilter and addTrackingStatusFilter
func addRegularilyUsedFilters(collection *csaf.CSAFDocumentCollection, r *http.Request) error {
	err := addBeforeFilter(collection, r)
	if err != nil {
		return err
	}
	err = addAfterFilter(collection, r)
	if err != nil {
		return err
	}
	err = addProfileFilter(collection, r)
	if err != nil {
		return err
	}
	err = addTrackingStatusFilter(collection, r)
	if err != nil {
		return err
	}
	return nil
}
