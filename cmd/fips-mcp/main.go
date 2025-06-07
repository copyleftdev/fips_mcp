// Copyright 2025 copyleftdev. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/copyleftdev/fips-mcp/internal/app"
	"github.com/copyleftdev/fips-mcp/internal/config"
	"github.com/copyleftdev/fips-mcp/pkg/version"
)

func main() {
	// Initialize configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Print version information if requested
	if cfg.ShowVersion {
		fmt.Println(version.String())
		return
	}

	// Create application instance
	application, err := app.New(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize application: %v", err)
	}

	// Setup signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	// Start the application
	go func() {
		if err := application.Start(ctx); err != nil {
			log.Printf("Application error: %v", err)
			cancel()
		}
	}()

	// Wait for termination signal
	sig := <-signalChan
	log.Printf("Received signal %v, shutting down...", sig)

	// Start graceful shutdown
	if err := application.Shutdown(context.Background()); err != nil {
		log.Printf("Error during shutdown: %v", err)
	}

	log.Println("Shutdown complete")
}
