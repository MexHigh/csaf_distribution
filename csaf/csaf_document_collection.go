package csaf

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// CSAFDocumentWrapper contains the actual document payload,
// it's hashes, signatures and a path relative to the
// CSAFDocumentCollections basePath.
type CSAFDocumentWrapper struct {
	Path      string
	Document  *CsafJson
	Hashes    *map[string]string
	Signature *string
}

// CSAFDocumentCollection holds all CSAF documents for the
// provider or aggregator and provides methods to interact
// with it.
type CSAFDocumentCollection struct {
	documents []CSAFDocumentWrapper
	filters   []func(doc *CsafJson) (bool, error)
}

// AddFilterFunc adds at least one filter function to the collection object
// without executing it. It can be called multiple times or with more than one
// function at once.
//
// To execute all filter functions, call StartFiltering().
func (dc *CSAFDocumentCollection) AddFilterFunc(f ...func(doc *CsafJson) (bool, error)) {
	dc.filters = append(dc.filters, f...)
}

// ClearFilterFuncs removes all filter functions. When calling
// StartFiltering(), the filter functions get cleared
// automatically afterwards.
func (dc *CSAFDocumentCollection) ClearFilterFuncs() {
	dc.filters = make([]func(doc *CsafJson) (bool, error), 0)
}

// StartFiltering executes all filter functions registered by
// AddFilterFunc() and returns the result. Afterwards, the
// registered filter functions are deleted.
func (dc *CSAFDocumentCollection) StartFiltering(verbose bool) ([]CSAFDocumentWrapper, error) {
	filteredDocuments := make([]CSAFDocumentWrapper, 0)

	for _, document := range dc.documents {
		matched := true
		for _, filter := range dc.filters {
			m, err := filter(document.Document)
			if err != nil {
				return nil, err
			}
			if !m {
				matched = false
				break
			}
		}
		if matched {
			filteredDocuments = append(filteredDocuments, document)
		}
	}

	if verbose {
		log.Printf("Matched %d documents", len(filteredDocuments))
	}
	// remove all used filters
	dc.ClearFilterFuncs()
	return filteredDocuments, nil
}

// NewCSAFDocumentCollection walks the basePath directory recursively to gather
// all CSAF documents within it and returns a new CSAFDocumentCollection instance.
func NewCSAFDocumentCollection(basePath string, verbose bool) (*CSAFDocumentCollection, error) {
	collection := make([]CSAFDocumentWrapper, 0)

	// regex for json files
	jsonFileRe, err := regexp.Compile("^(.*).json$")
	if err != nil {
		return nil, err
	}

	// walk the basePath directory recursivly to gather all CSAF documents
	err = filepath.WalkDir(basePath, func(path string, info fs.DirEntry, walkErr error) error {
		// skip html folder, if contained within basePath
		htmlPath := filepath.Join(basePath, "html")
		if strings.HasPrefix(path, htmlPath) {
			return nil
		}
		// skip folders
		if info.IsDir() {
			return nil
		}
		// skip files not ending in .json
		if !jsonFileRe.MatchString(info.Name()) {
			return nil
		}
		// skip iterations with error
		if walkErr != nil {
			return err
		}

		// read and decode the file to interface{} for validation
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		bytes, err := ioutil.ReadAll(file)
		if err != nil {
			return err
		}
		var doc interface{}
		err = json.Unmarshal(bytes, &doc)
		if err != nil {
			return err
		}

		// validate the loaded file
		// if it fails, skip (propably a ROLIE feed file)
		errors, err := ValidateCSAF(doc)
		if err != nil {
			return err
		}
		if len(errors) > 0 {
			return nil
		}

		// finally, unmarshal file into csaf.CsafJson
		var csafDoc CsafJson
		err = json.Unmarshal(bytes, &csafDoc)
		if err != nil {
			return err
		}

		// read signature
		var ascString string
		if ascFile, err := os.Open(path + ".asc"); err == nil {
			ascBytes, err := ioutil.ReadAll(ascFile)
			if err != nil {
				return err
			}
			ascFile.Close()
			ascString = string(ascBytes)
		}

		// read hashes
		var sha256String string
		if sha256File, err := os.Open(path + ".sha256"); err == nil {
			sha256Bytes, err := ioutil.ReadAll(sha256File)
			if err != nil {
				return err
			}
			sha256File.Close()
			sha256String = strings.Split(string(sha256Bytes), " ")[0] // strip filename
		}
		var sha512String string
		if sha512File, err := os.Open(path + ".sha512"); err == nil {
			sha512Bytes, err := ioutil.ReadAll(sha512File)
			if err != nil {
				return err
			}
			sha512File.Close()
			sha512String = strings.Split(string(sha512Bytes), " ")[0] // strip filename
		}

		// add the document to collection, depending on its TLP label
		tlpLabel := TLPLabel(csafDoc.Document.Distribution.Tlp.Label)
		switch tlpLabel {
		case TLPLabelWhite, TLPLabelGreen, TLPLabelAmber, TLPLabelRed:
			collection = append(collection, CSAFDocumentWrapper{
				Path:      strings.Split(path, basePath)[1], // path relative to basePath
				Document:  &csafDoc,
				Signature: &ascString,
				Hashes: &map[string]string{
					"sha256": sha256String,
					"sha512": sha512String,
				},
			})
		default:
			return fmt.Errorf("encountered csaf document with unknown TLP label: %s", string(tlpLabel))
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	// print report
	if verbose {
		log.Printf("Loaded %d CSAF documents", len(collection))
	}

	return &CSAFDocumentCollection{
		documents: collection,
		filters:   make([]func(doc *CsafJson) (bool, error), 0),
	}, nil
}
