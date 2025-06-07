// Copyright 2025 copyleftdev. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package app

import (
"context"
"fmt"
"log"
"net/http"
"os"
"os/signal"
"syscall"
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
	app := &App{
		config: cfg,
	}

	// Initialize HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/health", app.healthHandler)
	mux.HandleFunc("/ready", app.readyHandler)

	app.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  15 * time.Second,
	}

	return app, nil
}

// Start starts the application
func (a *App) Start(ctx context.Context) error {
	log.Printf("Starting server on %s", a.server.Addr)

	// Start server in a goroutine so it doesn't block
go func() {
if a.config.TLSEnabled {
if err := a.server.ListenAndServeTLS(a.config.CertFile, a.config.KeyFile); err != nil && err != http.ErrServerClosed {
log.Fatalf("Failed to start HTTPS server: %v", err)
}
} else {
if err := a.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
log.Fatalf("Failed to start HTTP server: %v", err)
}
}
}()

return nil
}

// Shutdown gracefully shuts down the application
func (a *App) Shutdown(ctx context.Context) error {
log.Println("Shutting down server...")
return a.server.Shutdown(ctx)
}

// healthHandler handles health check requests
func (a *App) healthHandler(w http.ResponseWriter, r *http.Request) {
w.Header().Set("Content-Type", "application/json")
w.WriteHeader(http.StatusOK)
w.Write([]byte(`{"status":"ok"}`))
}

// readyHandler handles readiness check requests
func (a *App) readyHandler(w http.ResponseWriter, r *http.Request) {
w.Header().Set("Content-Type", "application/json")
w.WriteHeader(http.StatusOK)
w.Write([]byte(`{"ready":true}`))
}
