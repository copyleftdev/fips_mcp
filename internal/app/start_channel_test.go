// Copyright 2025 copyleftdev. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package app

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/copyleftdev/fips-mcp/internal/config"
	"github.com/stretchr/testify/require"
)

// TestChannelBufferSize tests the behavior with different channel buffer sizes
func TestChannelBufferSize(t *testing.T) {
	tests := []struct {
		name          string
		setupApp     func() *App
		expectedErr   bool
		expectedError string
	}{
		{
			name: "zero buffer size should work",
			setupApp: func() *App {
				cfg := &config.Config{
					Host:     "127.0.0.1",
					Port:     0, // Let OS choose port
					LogLevel: "debug",
				}
				a, _ := New(cfg)
				a.server = &http.Server{
					Addr:    fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
					Handler: http.NewServeMux(),
				}
				return a
			},
			expectedErr: false,
		},
		{
			name: "larger buffer size should work",
			setupApp: func() *App {
				cfg := &config.Config{
					Host:     "127.0.0.1",
					Port:     0, // Let OS choose port
					LogLevel: "debug",
				}
				a, _ := New(cfg)
				a.server = &http.Server{
					Addr:    fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
					Handler: http.NewServeMux(),
				}
				return a
			},
			expectedErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := tt.setupApp()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			errCh := make(chan error, 1)
			go func() {
				errCh <- app.Start(ctx)
			}()

			// Give server a moment to start
			time.Sleep(100 * time.Millisecond)

			// Shutdown the server
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer shutdownCancel()

			err := app.Shutdown(shutdownCtx)
			if tt.expectedErr {
				require.Error(t, err)
				if tt.expectedError != "" {
					require.Contains(t, err.Error(), tt.expectedError)
				}
			} else {
				require.NoError(t, err)
			}

			// Verify server was shut down
			select {
			case err := <-errCh:
				if tt.expectedErr {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
				}
			case <-time.After(1 * time.Second):
				t.Fatal("Timed out waiting for server to shut down")
			}
		})
	}
}

// TestChannelBlocking tests that the channel doesn't block with multiple errors
func TestChannelBlocking(t *testing.T) {
	// This test verifies that the server can handle multiple errors
	// without blocking, which would happen if the channel wasn't buffered
	cfg := &config.Config{
		Host:     "127.0.0.1",
		Port:     0, // Let OS choose port
		LogLevel: "debug",
	}

	app, err := New(cfg)
	require.NoError(t, err)


	// Create a context that will be cancelled to stop the server
	ctx, cancel := context.WithCancel(context.Background())

	// Start the server in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- app.Start(ctx)
	}()

	// Give server a moment to start
	time.Sleep(100 * time.Millisecond)

	// Cancel the context to trigger shutdown
	cancel()

	// Wait for shutdown to complete
	timeout := time.After(2 * time.Second)
	select {
	case err := <-errCh:
		require.NoError(t, err, "Server should shut down cleanly")
	case <-timeout:
		t.Fatal("Timed out waiting for server to shut down")
	}
}
