// Copyright 2025 copyleftdev. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/copyleftdev/fips-mcp/internal/app"
	"github.com/copyleftdev/fips-mcp/internal/config"
	"github.com/copyleftdev/fips-mcp/pkg/version"
)

var (
	// versionFlag determines if the version information should be printed
	versionFlag = flag.Bool("version", false, "Print version information and exit")
)

func main() {
	// Create a context that cancels on interrupt signal
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

// run is the main entry point for the application
func run(ctx context.Context) error {
	// Parse flags
	flag.Parse()

	// Print version and exit if requested
	if *versionFlag {
		fmt.Println(version.String())
		return nil
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Create and start the application
	application, err := app.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create application: %w", err)
	}

	// Start the application in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- application.Start(ctx)
	}() // Fixed missing parentheses here

	// Wait for either the application to finish or context cancellation
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		// Context was cancelled, shutdown the application
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return application.Shutdown(shutdownCtx)
	}
}
