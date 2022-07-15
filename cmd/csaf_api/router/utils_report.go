package router

import (
	"encoding/json"
	"net/http"

	"github.com/csaf-poc/csaf_distribution/csaf"
)

// reportError can be used to report an error in the intended JSON schema.
// Always use a known, well-defined errcode.
//
// ATTENTION: Writing to the http.ResponseWriter does not end the request.
// subsequent calls to w.Write still reach the client. Always return your
// function after calling reportError.
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

// reportSuccess can be used to report a success message in the intended JSON
// schema with all documents. withHash and withSignature determines, whether
// the hashes or signature should be added to the reponse for every document,
// respectively.
//
// ATTENTION: Writing to the http.ResponseWriter does not end the request.
// subsequent calls to w.Write still reach the client.
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
