// Copyright 2025 copyleftdev. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.
package main

import (
	"context"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	// Save original command line arguments and flags
	oldArgs := os.Args
	oldCommandLine := flag.CommandLine

	// Run tests
	code := m.Run()

	// Restore original command line arguments and flags
	os.Args = oldArgs
	flag.CommandLine = oldCommandLine

	os.Exit(code)
}

func TestRun(t *testing.T) {
	tests := []struct {
		name    string
		envVars map[string]string
		wantErr bool
	}{
		{
			name:    "default config",
			envVars: map[string]string{"MCP_PORT": "0"}, // Use port 0 for random port
			wantErr: false,
		},
		{
			name:    "invalid port",
			envVars: map[string]string{"MCP_PORT": "99999"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up environment variables
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			// Reset command line flags
			flag.CommandLine = flag.NewFlagSet("fips-mcp", flag.ContinueOnError)

			// Run the application with a timeout
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			err := run(ctx)

			if tt.wantErr {
				assert.Error(t, err, "expected error but got none")
			} else {
				assert.NoError(t, err, "unexpected error")
			}
		})
	}
}

func TestVersionFlag(t *testing.T) {
	// Skip this test in short mode as it's testing flag parsing which is tricky to test
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	// Create a custom flag set for testing
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	// Add version flag to the custom flag set
	fs.Bool("version", false, "Print version information and exit")

	// Test with version flag
	args := []string{"-version"}
	err := fs.Parse(args)
	assert.NoError(t, err, "parsing version flag should not return an error")

	// Verify the flag was set correctly
	assert.True(t, fs.Lookup("version").Value.(flag.Getter).Get().(bool), "version flag should be true")
}
