// Copyright 2025 copyleftdev. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

// Package version provides version information for the application.
package version

import (
"fmt"
"runtime"
)

// These variables are set during build time using ldflags
var (
// Version is the semantic version of the application
Version = "dev"
// Commit is the git commit hash
Commit = "n/a"
// BuildTime is the time when the binary was built
BuildTime = "n/a"

// FIPSEnabled indicates if the binary was built with FIPS support
FIPSEnabled = "false"
)

// String returns a formatted string with version information
func String() string {
	return fmt.Sprintf(`Version:    %s
Git commit: %s
Build time: %s
Go version: %s
OS/Arch:    %s/%s
FIPS:       %s`,
Version,
Commit,
BuildTime,
runtime.Version(),
		runtime.GOOS,
		runtime.GOARCH,
		FIPSEnabled,
	)
}
