// Copyright 2025 copyleftdev. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package config

import (
	"flag"
	"os"
	"testing"
)

// ResetForTesting clears all flag state and sets the usage function as directed.
// After calling ResetForTesting, parse errors in flag handling will not
// exit the program.
func resetForTesting(usage func()) {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flag.Usage = usage
}


func TestLoad(t *testing.T) {
	tests := []struct {
		name        string
		envVars     map[string]string
		args        []string
		expectError bool
		validate    func(*testing.T, *Config)
	}{
		{
			name: "default config",
			envVars: map[string]string{},
			expectError: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Host != "0.0.0.0" {
					t.Errorf("expected Host to be '0.0.0.0', got '%s'", cfg.Host)
				}
				if cfg.Port != 8080 {
					t.Errorf("expected Port to be 8080, got %d", cfg.Port)
				}
				if cfg.LogLevel != "info" {
					t.Errorf("expected LogLevel to be 'info', got '%s'", cfg.LogLevel)
				}
			},
		},
		{
			name: "environment variables",
			envVars: map[string]string{
				"MCP_HOST":     "127.0.0.1",
				"MCP_PORT":     "3000",
				"MCP_LOG_LEVEL": "debug",
			},
			expectError: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Host != "127.0.0.1" {
					t.Errorf("expected Host to be '127.0.0.1', got '%s'", cfg.Host)
				}
				if cfg.Port != 3000 {
					t.Errorf("expected Port to be 3000, got %d", cfg.Port)
				}
				if cfg.LogLevel != "debug" {
					t.Errorf("expected LogLevel to be 'debug', got '%s'", cfg.LogLevel)
				}
			},
		},
		{
			name: "command line flags",
			envVars: map[string]string{},
			args: []string{
				"-host", "localhost",
				"-port", "4000",
				"-log-level", "warn",
			},
			expectError: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Host != "localhost" {
					t.Errorf("expected Host to be 'localhost', got '%s'", cfg.Host)
				}
				if cfg.Port != 4000 {
					t.Errorf("expected Port to be 4000, got %d", cfg.Port)
				}
				if cfg.LogLevel != "warn" {
					t.Errorf("expected LogLevel to be 'warn', got '%s'", cfg.LogLevel)
				}
			},
		},
		{
			name: "TLS config",
			envVars: map[string]string{
				"MCP_TLS_ENABLED":   "true",
				"MCP_TLS_CERT_FILE": "/path/to/cert.pem",
				"MCP_TLS_KEY_FILE":  "/path/to/key.pem",
			},
			expectError: false,
			validate: func(t *testing.T, cfg *Config) {
				if !cfg.TLSEnabled {
					t.Error("expected TLS to be enabled")
				}
				if cfg.CertFile != "/path/to/cert.pem" {
					t.Errorf("expected CertFile to be '/path/to/cert.pem', got '%s'", cfg.CertFile)
				}
				if cfg.KeyFile != "/path/to/key.pem" {
					t.Errorf("expected KeyFile to be '/path/to/key.pem', got '%s'", cfg.KeyFile)
				}
			},
		},
		{
			name: "invalid TLS config",
			envVars: map[string]string{
				"MCP_TLS_ENABLED": "true",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original command line arguments and environment variables
			oldArgs := os.Args
			defer func() { os.Args = oldArgs }()

			// Set up test command line arguments
			os.Args = append([]string{"test"}, tt.args...)

			// Set up environment variables
			for k, v := range tt.envVars {
				os.Setenv(k, v)
			}
			// Clean up environment variables after test
			defer func() {
				for k := range tt.envVars {
					os.Unsetenv(k)
				}
			}()

			// Reset flag command line to avoid "flag redefined" errors
			flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

			// Test the function
			cfg, err := Load()

			// Validate the results
			if tt.expectError && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tt.expectError && tt.validate != nil {
				tt.validate(t, cfg)
			}
		})
	}
}

func TestGetEnvAsInt(t *testing.T) {
	tests := []struct {
		name     string
		envVar   string
		value    string
		fallback int
		expected int
	}{
		{
			name:     "valid integer",
			envVar:   "TEST_INT",
			value:    "42",
			fallback: 0,
			expected: 42,
		},
		{
			name:     "invalid integer",
			envVar:   "TEST_INVALID_INT",
			value:    "not_an_int",
			fallback: 100,
			expected: 100,
		},
		{
			name:     "empty value",
			envVar:   "TEST_EMPTY",
			value:    "",
			fallback: 200,
			expected: 200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != "" {
				os.Setenv(tt.envVar, tt.value)
				defer os.Unsetenv(tt.envVar)
			}

			result := getEnvAsInt(tt.envVar, tt.fallback)
			if result != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestGetEnvAsBool(t *testing.T) {
	tests := []struct {
		name     string
		envVar   string
		value    string
		fallback bool
		expected bool
	}{
		{
			name:     "true value",
			envVar:   "TEST_BOOL",
			value:    "true",
			fallback: false,
			expected: true,
		},
		{
			name:     "1 value",
			envVar:   "TEST_BOOL_ONE",
			value:    "1",
			fallback: false,
			expected: true,
		},
		{
			name:     "false value",
			envVar:   "TEST_BOOL_FALSE",
			value:    "false",
			fallback: true,
			expected: false,
		},
		{
			name:     "invalid value",
			envVar:   "TEST_BOOL_INVALID",
			value:    "not_a_bool",
			fallback: true,
			expected: true,
		},
		{
			name:     "empty value",
			envVar:   "TEST_BOOL_EMPTY",
			value:    "",
			fallback: true,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != "" {
				os.Setenv(tt.envVar, tt.value)
				defer os.Unsetenv(tt.envVar)
			}

			result := getEnvAsBool(tt.envVar, tt.fallback)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}
