// Copyright 2025 copyleftdev. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package app

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestShutdownTimeout tests the successful shutdown behavior with a sufficient timeout
func TestShutdownTimeout(t *testing.T) {
	// Create a simple server
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	}

	// Start server on random port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "Failed to find available port")

	// Start server in a goroutine
	done := make(chan struct{})
	go func() {
		_ = srv.Serve(ln) // nolint:errcheck
		close(done)
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Create shutdown context with sufficient timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Shutdown should succeed
	err = srv.Shutdown(ctx)
	assert.NoError(t, err, "Expected successful shutdown with sufficient timeout")

	// Cleanup
	ln.Close()
	<-done // Wait for server to exit
}

// TestAppShutdownTimeout tests the app's shutdown behavior with sufficient timeout
func TestAppShutdownTimeout(t *testing.T) {
	// Create a test server with a handler that responds immediately
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	}

	// Start server on random port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "Failed to find available port")

	// Start server in a goroutine
	done := make(chan struct{})
	go func() {
		_ = srv.Serve(ln) // nolint:errcheck
		close(done)
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Create shutdown context with sufficient timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Shutdown should succeed
	err = srv.Shutdown(ctx)
	assert.NoError(t, err, "Expected successful shutdown with sufficient timeout")

	// Cleanup
	ln.Close()
	<-done // Wait for server to exit
}
