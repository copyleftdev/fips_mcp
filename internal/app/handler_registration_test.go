// Copyright 2025 copyleftdev. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package app

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/copyleftdev/fips-mcp/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHandlerRegistration verifies that all expected HTTP handlers are registered
func TestHandlerRegistration(t *testing.T) {
	tests := []struct {
		name           string
		method        string
		path          string
		expectedCode  int
		expectedBody  string
		expectedError bool
	}{
		{
			name:          "health check GET",
			method:       http.MethodGet,
			path:         "/healthz",
			expectedCode:  http.StatusOK,
			expectedBody:  `{"status":"ok"}`,
			expectedError: false,
		},
		{
			name:          "health check POST",
			method:       http.MethodPost,
			path:         "/healthz",
			expectedCode:  http.StatusMethodNotAllowed,
			expectedBody:  "Method not allowed",
			expectedError: false,
		},
		{
			name:          "readiness check GET",
			method:       http.MethodGet,
			path:         "/readyz",
			expectedCode:  http.StatusOK,
			expectedBody:  `{"status":"ready"}`,
			expectedError: false,
		},
		{
			name:          "readiness check POST",
			method:       http.MethodPost,
			path:         "/readyz",
			expectedCode:  http.StatusMethodNotAllowed,
			expectedBody:  "Method not allowed",
			expectedError: false,
		},
		{
			name:          "non-existent endpoint",
			method:       http.MethodGet,
			path:         "/nonexistent",
			expectedCode:  http.StatusNotFound,
			expectedBody:  "404 page not found",
			expectedError: false,
		},
	}

	// Create a test server with the actual app handlers
	cfg := &config.Config{
		Host:     "127.0.0.1",
		Port:     0, // Let OS choose port
		LogLevel: "debug",
	}

	app, err := New(cfg)
	require.NoError(t, err, "Failed to create app")

	server := httptest.NewServer(app.server.Handler)
	defer server.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, server.URL+tt.path, nil)
			require.NoError(t, err, "Failed to create request")

			resp, err := http.DefaultClient.Do(req)
			if tt.expectedError {
				assert.Error(t, err, "Expected request to fail")
				return
			}

			require.NoError(t, err, "Request failed")
			defer resp.Body.Close()

			// Verify status code
			assert.Equal(t, tt.expectedCode, resp.StatusCode, "Unexpected status code")


			// Verify response body
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err, "Failed to read response body")

			// Normalize line endings for comparison
			bodyStr := string(bytes.TrimSpace(bytes.ReplaceAll(body, []byte("\r\n"), []byte("\n"))))
			expected := tt.expectedBody
			if bodyStr != expected {
				t.Errorf("Unexpected response body. Expected: %q, got: %q", expected, bodyStr)
			}

			// Verify content type for successful responses
			if resp.StatusCode == http.StatusOK {
				contentType := resp.Header.Get("Content-Type")
				assert.Equal(t, "application/json", contentType, "Unexpected Content-Type header")
			}
		})
	}
}

// TestMiddlewareRegistration verifies that any middleware is correctly applied
func TestMiddlewareRegistration(t *testing.T) {
	// This test can be expanded if you add middleware to your application
	// For now, it just verifies that the basic handlers work with the current setup
	tests := []struct {
		name     string
		path     string
		method   string
		expected string
	}{
		{
			name:     "health check",
			path:     "/healthz",
			method:   http.MethodGet,
			expected: `{"status":"ok"}`,
		},
		{
			name:     "readiness check",
			path:     "/readyz",
			method:   http.MethodGet,
			expected: `{"status":"ready"}`,
		},
	}

	// Create a test server with the actual app handlers
	cfg := &config.Config{
		Host:     "127.0.0.1",
		Port:     0, // Let OS choose port
		LogLevel: "debug",
	}

	app, err := New(cfg)
	require.NoError(t, err, "Failed to create app")

	server := httptest.NewServer(app.server.Handler)
	defer server.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, server.URL+tt.path, nil)
			require.NoError(t, err, "Failed to create request")

			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err, "Request failed")
			defer resp.Body.Close()

			// Verify status code
			assert.Equal(t, http.StatusOK, resp.StatusCode, "Unexpected status code")


			// Verify response body
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err, "Failed to read response body")

			assert.JSONEq(t, tt.expected, string(body), "Unexpected response body")

			// Verify content type
			contentType := resp.Header.Get("Content-Type")
			assert.Equal(t, "application/json", contentType, "Unexpected Content-Type header")
		})
	}
}
