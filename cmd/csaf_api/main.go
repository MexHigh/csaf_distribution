/*
 * Common Security Advisory Framework (CSAF) 2.0 Distribution API
 *
 * Base file
 *
 * API version: 0.1.1
 * Contact: pending@example.com
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package main

import (
	"log"
	"net/http"

	"github.com/jessevdk/go-flags"

	"github.com/csaf-poc/csaf_distribution/cmd/csaf_api/config"
	"github.com/csaf-poc/csaf_distribution/cmd/csaf_api/router"
	"github.com/csaf-poc/csaf_distribution/csaf"
)

type options struct {
	Config string `short:"c" long:"config" description:"File name of the configuration file" value-name:"CFG-FILE" default:"api.toml"`
}

func main() {
	opts := new(options)
	_, err := flags.Parse(opts)
	if err != nil {
		log.Fatalf("error: %v\n", err)
	}

	log.Println("Loading config")
	c, err := config.Load(opts.Config)
	if err != nil {
		log.Fatalf("error: %v\n", err)
	}

	log.Println("Loading all CSAF documents")
	collection, err := csaf.NewCSAFDocumentCollection(c.CSAFDocumentsPath, c.Verbose)
	if err != nil {
		log.Fatalf("error: %v\n", err)
	}
	// IDEA: this can be called regularly (e.g. in a gorouting)
	// to refetch all documents from time to time

	// TEMP
	/*for _, doc := range (*allDocuments)[csaf.TLPLabelRed] {
		fmt.Println(doc.Document.Distribution.Tlp.Label)
		fmt.Println(doc.Document.Title)
	}*/

	log.Println("Loading API server routes")
	router := router.NewAPI(
		string(c.UsedIn),
		c.Auth,
		collection,
	)

	log.Println("Starting API server")
	log.Fatal(http.ListenAndServe(c.BindAddress, router))
}
