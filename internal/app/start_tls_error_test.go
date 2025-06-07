// Copyright 2025 copyleftdev. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package app

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/copyleftdev/fips-mcp/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStartTLSFailure tests the error path in Start when TLS fails to start
func TestStartTLSFailure(t *testing.T) {
	// Create a temporary directory for this test
	tempDir := t.TempDir()
	
	// Create a dummy cert file but no key file
	dummyCert := filepath.Join(tempDir, "cert.pem")
	if err := os.WriteFile(dummyCert, []byte("dummy cert"), 0644); err != nil {
		t.Fatalf("Failed to create dummy cert file: %v", err)
	}

	// Create a config with TLS enabled but with a non-existent key file
	cfg := &config.Config{
		Host:       "127.0.0.1",
		Port:       0, // Let the OS choose an available port
		LogLevel:   "debug",
		TLSEnabled: true,
		CertFile:   dummyCert,
		KeyFile:    filepath.Join(tempDir, "nonexistent.key"),
	}

	// Create a new app
	app, err := New(cfg)
	require.NoError(t, err, "Failed to create app")

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Start the server - this should fail because the key file doesn't exist
	err = app.Start(ctx)
	assert.Error(t, err, "Expected error when starting with missing TLS key file")
	assert.Contains(t, err.Error(), "nonexistent.key: no such file or directory", "Expected file not found error")
}

// TestStartTLSSuccess tests the successful TLS server startup
// generateSelfSignedCert creates a self-signed certificate and key for testing
func generateSelfSignedCert(t *testing.T) (certFile, keyFile string, cleanup func()) {
	t.Helper()

	tempDir := t.TempDir()
	certFile = filepath.Join(tempDir, "cert.pem")
	keyFile = filepath.Join(tempDir, "key.pem")

	// Generate a new RSA private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Create a self-signed certificate template
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create a self-signed certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Write certificate to file
	certOut, err := os.Create(certFile)
	if err != nil {
		t.Fatalf("Failed to open cert.pem for writing: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		certOut.Close()
		t.Fatalf("Failed to write data to cert.pem: %v", err)
	}
	if err := certOut.Close(); err != nil {
		t.Fatalf("Error closing cert.pem: %v", err)
	}

	// Write private key to file
	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatalf("Failed to open key.pem for writing: %v", err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("Unable to marshal private key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		keyOut.Close()
		t.Fatalf("Failed to write data to key.pem: %v", err)
	}
	if err := keyOut.Close(); err != nil {
		t.Fatalf("Error closing key.pem: %v", err)
	}

	// Return the file paths and a cleanup function
	cleanup = func() {
		os.Remove(certFile)
		os.Remove(keyFile)
	}

	return certFile, keyFile, cleanup
}

func TestStartTLSSuccess(t *testing.T) {
	// Generate self-signed certificate for testing
	certFile, keyFile, cleanup := generateSelfSignedCert(t)
	defer cleanup()

	// Create a config with TLS enabled
	cfg := &config.Config{
		Host:       "127.0.0.1",
		Port:       0, // Let the OS choose an available port
		LogLevel:   "debug",
		TLSEnabled: true,
		CertFile:   certFile,
		KeyFile:    keyFile,
	}

	// Create a new app
	app, err := New(cfg)
	require.NoError(t, err, "Failed to create app")

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Start the server in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- app.Start(ctx)
	}()

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)

	// Shutdown the server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer shutdownCancel()
	err = app.Shutdown(shutdownCtx)
	assert.NoError(t, err, "Shutdown should not return an error")

	// Verify the server was shut down
	select {
	case err := <-errCh:
		assert.NoError(t, err, "Server should have started and shut down cleanly")
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for server to shut down")
	}
}


