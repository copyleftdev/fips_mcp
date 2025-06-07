// Copyright 2025 copyleftdev. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package app

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/copyleftdev/fips-mcp/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHealthCheckHandler(t *testing.T) {
	tests := []struct {
		name          string
		method       string
		expectStatus int
		expectHeaders map[string]string
		expectBody   string
	}{
		{
			name:          "GET request",
			method:        http.MethodGet,
			expectStatus:  http.StatusOK,
			expectHeaders: map[string]string{
				"Content-Type": "application/json",
			},
			expectBody: `{"status":"ok"}`,
		},
		{
			name:          "POST request",
			method:        http.MethodPost,
			expectStatus:  http.StatusMethodNotAllowed,
			expectHeaders: map[string]string{
				"Content-Type": "text/plain; charset=utf-8",
				"X-Content-Type-Options": "nosniff",
			},
			expectBody: "Method not allowed\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, "/healthz", nil)
			require.NoError(t, err)

			rr := httptest.NewRecorder()
			handler := http.HandlerFunc(HealthCheckHandler)

			handler.ServeHTTP(rr, req)

			// Check status code
			assert.Equal(t, tt.expectStatus, rr.Code, "Unexpected status code")
			
			// Check response headers
			for key, expectedValue := range tt.expectHeaders {
				actualValue := rr.Header().Get(key)
				assert.Equal(t, expectedValue, actualValue, "Header %s mismatch", key)
			}
			
			// Verify response body
			if tt.expectBody != "" {
				assert.Equal(t, tt.expectBody, rr.Body.String(), "Unexpected response body")
			}
		})
	}
}

func TestReadinessCheckHandler(t *testing.T) {
	tests := []struct {
		name          string
		method       string
		expectStatus int
		expectHeaders map[string]string
		expectBody   string
	}{
		{
			name:          "GET request",
			method:        http.MethodGet,
			expectStatus:  http.StatusOK,
			expectHeaders: map[string]string{
				"Content-Type": "application/json",
			},
			expectBody: `{"status":"ready"}`,
		},
		{
			name:          "POST request",
			method:        http.MethodPost,
			expectStatus:  http.StatusMethodNotAllowed,
			expectHeaders: map[string]string{
				"Content-Type": "text/plain; charset=utf-8",
				"X-Content-Type-Options": "nosniff",
			},
			expectBody: "Method not allowed\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, "/readyz", nil)
			require.NoError(t, err, "Failed to create request")

			rr := httptest.NewRecorder()
			handler := http.HandlerFunc(ReadinessCheckHandler)

			handler.ServeHTTP(rr, req)

			// Check status code
			assert.Equal(t, tt.expectStatus, rr.Code, "Unexpected status code")
			
			// Check response headers
			for key, expectedValue := range tt.expectHeaders {
				actualValue := rr.Header().Get(key)
				assert.Equal(t, expectedValue, actualValue, "Header %s mismatch", key)
			}
			
			// Verify response body
			if tt.expectBody != "" {
				assert.Equal(t, tt.expectBody, rr.Body.String(), "Unexpected response body")
			}
		})
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		config  *config.Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: &config.Config{
				Host: "localhost",
				Port: 8080,
			},
			wantErr: false,
		},
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
			errMsg:  "config cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, err := New(tt.config)
			
			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, app)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
				require.NotNil(t, app)
				assert.Equal(t, tt.config, app.config)
				
				// Verify HTTP server is properly configured
				assert.Equal(t, fmt.Sprintf("%s:%d", tt.config.Host, tt.config.Port), app.server.Addr)
				
				// Verify handlers are registered
				handler, _ := app.server.Handler.(*http.ServeMux).Handler(&http.Request{
					Method: http.MethodGet,
					URL:    &url.URL{Path: "/healthz"},
				})
				assert.NotNil(t, handler, "Health check handler not registered")
				
				handler, _ = app.server.Handler.(*http.ServeMux).Handler(&http.Request{
					Method: http.MethodGet,
					URL:    &url.URL{Path: "/readyz"},
				})
				assert.NotNil(t, handler, "Readiness check handler not registered")
			}
		})
	}
}
