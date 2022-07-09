package config

import (
	"github.com/BurntSushi/toml"

	"github.com/csaf-poc/csaf_distribution/csaf"
)

const (
	defaultConfigPath        = "api.toml"
	defaultBindAddress       = "0.0.0.0:8080"
	defaultCSAFDocumentsPath = "/var/www"
)

type AuthData struct {
	// The token without the "Bearer" part
	Token string `toml:"token"`
	// Slice containing all TLP labels this token has clearence for
	// (TLP:WHITE is always implicitly included)
	AllowedTLPLabels []csaf.TLPLabel `toml:"allowed_tlp_labels"`
}

type Config struct {
	// Whether to print verbose logs
	Verbose bool `toml:"verbose"` // default: false (implicit)
	// The address with port, the API should listen on
	BindAddress string `toml:"bind_address"` // default: 0.0.0.0:8080
	// The path, where all CSAF documents reside in
	// (see 'web' provider option (https://github.com/csaf-poc/csaf_distribution/blob/main/docs/csaf_provider.md))
	CSAFDocumentsPath string `toml:"csaf_documents_path"` // default: /var/www
	// Slice containing tokens that can be used to request
	// TLP:GREEN, TLP:AMBER or TLP:RED documents
	Auth []AuthData `toml:"auth"`
	// Defines, in which CSAF component the API is used in
	UsedIn csaf.MetadataRole `toml:"used_in"` // TODO check for correct value
}

func (c *Config) setDefaults() {
	if c.BindAddress == "" {
		c.BindAddress = defaultBindAddress
	}
	if c.CSAFDocumentsPath == "" {
		c.CSAFDocumentsPath = defaultCSAFDocumentsPath
	}
}

func Load(path string) (*Config, error) {
	if path == "" {
		path = defaultConfigPath
	}

	var c Config
	if _, err := toml.DecodeFile(path, &c); err != nil {
		return nil, err
	}

	c.setDefaults()

	return &c, nil
}
