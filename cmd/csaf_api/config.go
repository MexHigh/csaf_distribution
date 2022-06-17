package main

import (
	"github.com/BurntSushi/toml"
)

const (
	defaultConfigPath        = "api.toml"
	defaultBindAddress       = "0.0.0.0:8080"
	defaultCSAFDocumentsPath = "/var/www"
)

type config struct {
	// Whether to print verbose logs
	Verbose bool `toml:"verbose"` // default: false (implicit)
	// The address with port, the API should listen to.
	BindAddress string `toml:"bind_address"` // default: 0.0.0.0:8080
	// The path, where all CSAF documents reside in
	// (see 'web' provider option (https://github.com/MexHigh/csaf_distribution/blob/main/docs/csaf_provider.md))
	CSAFDocumentsPath string `toml:"csaf_documents_path"` // default: /var/www
}

func (c *config) setDefaults() {
	if c.BindAddress == "" {
		c.BindAddress = defaultBindAddress
	}
	if c.CSAFDocumentsPath == "" {
		c.CSAFDocumentsPath = defaultCSAFDocumentsPath
	}
}

func loadConfig(path string) (*config, error) {
	if path == "" {
		path = defaultConfigPath
	}

	var c config
	if _, err := toml.DecodeFile(path, &c); err != nil {
		return nil, err
	}

	c.setDefaults()

	return &c, nil
}
