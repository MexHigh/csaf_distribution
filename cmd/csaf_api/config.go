package main

import (
	"github.com/BurntSushi/toml"
)

const (
	defaultConfigPath  = "api.toml"
	defaultBindAddress = "0.0.0.0:8080"
)

type config struct {
	// The address with port, the API should listen to.
	//
	// Default: 0.0.0.0:8080
	BindAddress string `toml:"bind_address"`
}

func (c *config) setDefaults() {
	if c.BindAddress == "" {
		c.BindAddress = defaultBindAddress
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
