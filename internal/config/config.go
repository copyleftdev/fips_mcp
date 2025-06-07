// Copyright 2025 copyleftdev. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package config

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config holds all configuration for the application
type Config struct {
	// Server configuration
	Host         string
	Port         int
	TLSEnabled   bool
	CertFile     string
	KeyFile      string

	// Logging
	LogLevel     string
	LogFormat    string

	// Feature flags
	EnableFIPS   bool

	// CLI flags
	ShowVersion  bool
}

// Load loads the configuration from environment variables and command line flags
func Load() (*Config, error) {
	cfg := &Config{
		Host:       getEnv("MCP_HOST", "0.0.0.0"),
		Port:       getEnvAsInt("MCP_PORT", 8080),
		TLSEnabled: getEnvAsBool("MCP_TLS_ENABLED", false),
		CertFile:   getEnv("MCP_TLS_CERT_FILE", ""),
		KeyFile:    getEnv("MCP_TLS_KEY_FILE", ""),
		LogLevel:   getEnv("MCP_LOG_LEVEL", "info"),
		LogFormat:  getEnv("MCP_LOG_FORMAT", "text"),
		EnableFIPS: getEnvAsBool("MCP_FIPS_ENABLED", true),
	}

	// Parse command line flags
	flag.BoolVar(&cfg.ShowVersion, "version", false, "Show version information and exit")
	flag.StringVar(&cfg.Host, "host", cfg.Host, "Host to bind the server to")
	flag.IntVar(&cfg.Port, "port", cfg.Port, "Port to bind the server to")
	flag.BoolVar(&cfg.TLSEnabled, "tls-enabled", cfg.TLSEnabled, "Enable TLS")
	flag.StringVar(&cfg.CertFile, "tls-cert-file", cfg.CertFile, "Path to TLS certificate file")
	flag.StringVar(&cfg.KeyFile, "tls-key-file", cfg.KeyFile, "Path to TLS key file")
	flag.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "Log level (debug, info, warn, error, fatal)")
	flag.StringVar(&cfg.LogFormat, "log-format", cfg.LogFormat, "Log format (text, json)")
	flag.BoolVar(&cfg.EnableFIPS, "fips-enabled", cfg.EnableFIPS, "Enable FIPS 140-3 compliance mode")

	flag.Parse()

	// Validate configuration
	if cfg.TLSEnabled && (cfg.CertFile == "" || cfg.KeyFile == "") {
		return nil, fmt.Errorf("TLS is enabled but certificate or key file is not specified")
	}

	return cfg, nil
}

// Helper functions for environment variable parsing
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func getEnvAsInt(key string, fallback int) int {
	if value, exists := os.LookupEnv(key); exists {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return fallback
}

func getEnvAsBool(key string, fallback bool) bool {
	if value, exists := os.LookupEnv(key); exists {
		// Check for true values
		if strings.ToLower(value) == "true" || value == "1" {
			return true
		}
		// Check for false values
		if strings.ToLower(value) == "false" || value == "0" {
			return false
		}
		// For any other value, return fallback
		return fallback
	}
	return fallback
}
