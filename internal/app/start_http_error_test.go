// Copyright 2025 copyleftdev. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package app

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/copyleftdev/fips-mcp/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStartHTTPError tests the error path in Start when the HTTP server fails to start
func TestStartHTTPError(t *testing.T) {
	// Create a listener on a random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "Failed to create listener")
	defer listener.Close()

	// Get the port the listener is using
	addr := listener.Addr().String()
	_, port, err := net.SplitHostPort(addr)
	require.NoError(t, err, "Failed to get port from listener")

	// Create a config that will try to use the same port
	cfg := &config.Config{
		Host:       "127.0.0.1",
		Port:       0, // Will be set below
		LogLevel:   "debug",
		TLSEnabled: false,
	}

	// Parse the port number
	var portInt int
	_, err = fmt.Sscanf(port, "%d", &portInt)
	require.NoError(t, err, "Failed to parse port number")
	cfg.Port = portInt

	// Create a new app
	app, err := New(cfg)
	require.NoError(t, err, "Failed to create app")

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Start the server - this should fail because the port is already in use
	err = app.Start(ctx)
	assert.Error(t, err, "Expected error when starting server on used port")
	assert.Contains(t, err.Error(), "bind: address already in use", "Expected address in use error")
}

// TestStartWithContextCancellation tests the context cancellation path in Start
func TestStartWithContextCancellation(t *testing.T) {
	// Create a config with a random port
	cfg := &config.Config{
		Host:       "127.0.0.1",
		Port:       0, // Let the OS choose an available port
		LogLevel:   "debug",
		TLSEnabled: false,
	}

	// Create a new app
	app, err := New(cfg)
	require.NoError(t, err, "Failed to create app")

	// Create a context that will be cancelled immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Start the server with the cancelled context
	err = app.Start(ctx)
	assert.NoError(t, err, "Start should not return an error when context is cancelled")

	// Verify the server is not running by trying to start it again
	err = app.Start(context.Background())
	assert.NoError(t, err, "Should be able to start server after context cancellation")

	// Cleanup
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer shutdownCancel()
	err = app.Shutdown(shutdownCtx)
	assert.NoError(t, err, "Shutdown should not return an error")
}
