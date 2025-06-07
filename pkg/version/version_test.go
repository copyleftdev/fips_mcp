// Copyright 2025 copyleftdev. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package version

import (
	"testing"
)

func TestString(t *testing.T) {
	tests := []struct {
		name     string
		setup    func()
		testFunc func(t *testing.T)
	}{
		{
			name: "default version",
			setup: func() {
				// Reset to default values
				Version = "dev"
				Commit = "n/a"
				BuildTime = "n/a"
				FIPSEnabled = "false"
			},
			testFunc: func(t *testing.T) {
				result := String()
				if result == "" {
					t.Error("String() returned an empty string")
				}
			},
		},
		{
			name: "custom version",
			setup: func() {
				Version = "v1.0.0"
				Commit = "abc123"
				BuildTime = "2025-01-01T00:00:00Z"
				FIPSEnabled = "true"
			},
			testFunc: func(t *testing.T) {
				result := String()
				if result == "" {
					t.Error("String() returned an empty string")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			originalVersion := Version
			originalCommit := Commit
			originalBuildTime := BuildTime
			originalFIPS := FIPSEnabled

			// Run setup
			tt.setup()

			// Run test function
			tt.testFunc(t)

			// Restore original values
			Version = originalVersion
			Commit = originalCommit
			BuildTime = originalBuildTime
			FIPSEnabled = originalFIPS
		})
	}
}
