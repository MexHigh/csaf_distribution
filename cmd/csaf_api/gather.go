package main

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

	"github.com/csaf-poc/csaf_distribution/csaf"
)

// csafDocumentCollection maps a TLP Label to a
// slice of CSAF Documents
type csafDocumentCollection map[csaf.TLPLabel][]csaf.CsafJson

// gatherAllCSAFDocuments walks the basePath directory recursively to gather
// all CSAF documents within it. They are
func gatherAllCSAFDocuments(basePath string, verbose bool) (*csafDocumentCollection, error) {
	collection := csafDocumentCollection{
		"white": make([]csaf.CsafJson, 0),
		"green": make([]csaf.CsafJson, 0),
		"amber": make([]csaf.CsafJson, 0),
		"red":   make([]csaf.CsafJson, 0),
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
		errors, err := csaf.ValidateCSAF(doc)
		if err != nil {
			return err
		}
		if len(errors) > 0 {
			return nil
		}

		// finally, unmarshal file into csaf.CsafJson
		var csafDoc csaf.CsafJson
		err = json.Unmarshal(bytes, &csafDoc)
		if err != nil {
			return err
		}

		// add the document to collection, depending on its TLP label
		tlpLabel := csaf.TLPLabel(csafDoc.Document.Distribution.Tlp.Label)
		switch tlpLabel {
		case csaf.TLPLabelWhite, csaf.TLPLabelGreen, csaf.TLPLabelAmber, csaf.TLPLabelRed:
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
		log.Printf("Loaded %d CSAF documents with TLP:WHITE", len(collection[csaf.TLPLabelWhite]))
		log.Printf("Loaded %d CSAF documents with TLP:GREEN", len(collection[csaf.TLPLabelGreen]))
		log.Printf("Loaded %d CSAF documents with TLP:AMBER", len(collection[csaf.TLPLabelAmber]))
		log.Printf("Loaded %d CSAF documents with TLP:RED", len(collection[csaf.TLPLabelRed]))
	}

	return &collection, nil
}
