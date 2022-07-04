package router

import (
	"encoding/json"
	"net/http"

	"github.com/csaf-poc/csaf_distribution/csaf"
)

func reportError(w *http.ResponseWriter, statusCode int, errcode, errmsg string) {
	obj := CsafDocumentResponse{
		Error: &ModelError{
			Errcode: errcode,
			Errmsg:  errmsg,
		},
		DocumentsFound: 0,
		Documents:      nil,
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
		Error:          nil,
		DocumentsFound: len(documents),
		Documents:      documents,
	}

	v, err := json.MarshalIndent(obj, "", "    ")
	if err != nil {
		reportError(w, 500, "UNKNOWN", "Unable to marshal reponse object")
		return
	}

	(*w).Header().Set("Content-Type", "application/json; charset=UTF-8")
	(*w).WriteHeader(http.StatusOK)
	(*w).Write(v)
}
