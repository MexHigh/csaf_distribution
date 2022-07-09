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

// CSAFDocumentCollection holds all CSAF documents for the
// provider or aggregator and provides methods to interact
// with it.
type CSAFDocumentCollection struct {
	documents map[TLPLabel][]CsafJson
	filters   []func(doc *CsafJson) bool
}

// AddFilterFunc adds at least one filter function to the collection object
// without executing it. It can be called multiple times or with more than one
// function at once.
//
// To execute all filter functions, call StartFiltering().
func (dc *CSAFDocumentCollection) AddFilterFunc(f ...func(doc *CsafJson) bool) {
	dc.filters = append(dc.filters, f...)
}

// ClearFilterFuncs removes all filter functions. When calling
// StartFiltering, the filter function get cleared automatically.
func (dc *CSAFDocumentCollection) ClearFilterFuncs() {
	dc.filters = make([]func(doc *CsafJson) bool, 0)
}

// StartFiltering executes all filter functions registered by
// AddFilterFunc() and applies the result directly to the collection.
// Afterwards, the registered filter functions are deleted.
func (dc *CSAFDocumentCollection) StartFiltering(verbose bool) error {
	for tlp, documents := range dc.documents {
		if verbose {
			log.Printf("Processing TLP:%s documents", string(tlp))
		}
		newDocuments := make([]CsafJson, 0)
		for _, document := range documents {
			matched := true
			for _, filter := range dc.filters {
				if !filter(&document) {
					matched = false
					break
				}
			}
			if matched {
				newDocuments = append(newDocuments, document)
			}
		}
		dc.documents[tlp] = newDocuments
		if verbose {
			log.Printf("Matched %d documents", len(newDocuments))
		}
	}
	// remove all used filters
	dc.ClearFilterFuncs()
	return nil
}

// GetCurrentDocuments returns a CSAF document slice mapped to TLP labels.
func (dc *CSAFDocumentCollection) GetCurrentDocuments() map[TLPLabel][]CsafJson {
	return dc.documents
}

// GetCurrentDocumentsMerged returns a CSAF document slice
// merged from all TLP labels.
func (dc *CSAFDocumentCollection) GetCurrentDocumentsMerged() []CsafJson {
	merged := make([]CsafJson, 0)
	for _, documents := range dc.documents {
		merged = append(merged, documents...)
	}
	return merged
}

// NewCSAFDocumentCollection walks the basePath directory recursively to gather
// all CSAF documents within it and returns a new CSAFDocumentCollection instance.
func NewCSAFDocumentCollection(basePath string, verbose bool) (*CSAFDocumentCollection, error) {
	collection := map[TLPLabel][]CsafJson{
		"WHITE": make([]CsafJson, 0),
		"GREEN": make([]CsafJson, 0),
		"AMBER": make([]CsafJson, 0),
		"RED":   make([]CsafJson, 0),
	}

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

		// add the document to collection, depending on its TLP label
		tlpLabel := TLPLabel(csafDoc.Document.Distribution.Tlp.Label)
		switch tlpLabel {
		case TLPLabelWhite, TLPLabelGreen, TLPLabelAmber, TLPLabelRed:
			collection[tlpLabel] = append(collection[tlpLabel], csafDoc)
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
		log.Printf("Loaded %d CSAF documents with TLP:WHITE", len(collection[TLPLabelWhite]))
		log.Printf("Loaded %d CSAF documents with TLP:GREEN", len(collection[TLPLabelGreen]))
		log.Printf("Loaded %d CSAF documents with TLP:AMBER", len(collection[TLPLabelAmber]))
		log.Printf("Loaded %d CSAF documents with TLP:RED", len(collection[TLPLabelRed]))
	}

	return &CSAFDocumentCollection{
		documents: collection,
		filters:   make([]func(doc *CsafJson) bool, 0),
	}, nil
}
