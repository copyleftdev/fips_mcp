// Copyright 2025 copyleftdev. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package app

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/copyleftdev/fips-mcp/internal/config"
)

// App represents the main application
type App struct {
	config *config.Config
	server *http.Server
}

// New creates a new application instance
func New(cfg *config.Config) (*App, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	r := http.NewServeMux()
	r.HandleFunc("/healthz", HealthCheckHandler)
	r.HandleFunc("/readyz", ReadinessCheckHandler)

	srv := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Handler: r,
	}

	return &App{
		config: cfg,
		server: srv,
	}, nil
}

// Start starts the application
func (a *App) Start(ctx context.Context) error {
	log.Printf("Starting server on %s", a.server.Addr)

	serverErr := make(chan error, 1)
	go func() {
		if a.config.TLSEnabled {
			if err := a.server.ListenAndServeTLS(a.config.CertFile, a.config.KeyFile); err != nil && err != http.ErrServerClosed {
				serverErr <- fmt.Errorf("HTTPS server error: %w", err)
				return
			}
		} else {
			if err := a.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				serverErr <- fmt.Errorf("HTTP server error: %w", err)
				return
			}
		}
		serverErr <- nil
	}()

	// Wait for either server error or context cancellation
	select {
	case err := <-serverErr:
		return err
	case <-ctx.Done():
		// Context was cancelled, shutdown the server
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return a.Shutdown(shutdownCtx)
	}
}

// Shutdown gracefully shuts down the application
func (a *App) Shutdown(ctx context.Context) error {
	log.Println("Shutting down server...")
	return a.server.Shutdown(ctx)
}

// HealthCheckHandler handles health check requests
func HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"ok"}`)
}

// ReadinessCheckHandler handles readiness check requests
func ReadinessCheckHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"ready"}`)
}
