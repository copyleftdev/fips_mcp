// Copyright 2025 copyleftdev. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package engine

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockKeyStore is an in-memory implementation of KeyStore for testing
type mockKeyStore struct {
	keys map[string]crypto.PrivateKey
}

func newMockKeyStore() *mockKeyStore {
	return &mockKeyStore{
		keys: make(map[string]crypto.PrivateKey),
	}
}

func (m *mockKeyStore) GetKey(id string) (crypto.PrivateKey, error) {
	key, exists := m.keys[id]
	if !exists {
		return nil, os.ErrNotExist
	}
	return key, nil
}

func (m *mockKeyStore) StoreKey(id string, key crypto.PrivateKey) error {
	m.keys[id] = key
	return nil
}

func (m *mockKeyStore) DeleteKey(id string) error {
	delete(m.keys, id)
	return nil
}

func TestNewEngine(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid config with FIPS enabled",
			config: Config{
				FIPSEnabled: true,
				KeyStore:    newMockKeyStore(),
			},
			wantErr: false,
		},
		{
			name: "valid config with FIPS disabled",
			config: Config{
				FIPSEnabled: false,
				KeyStore:    newMockKeyStore(),
			},
			wantErr: false,
		},
		{
			name: "missing key store",
			config: Config{
				FIPSEnabled: true,
				KeyStore:    nil,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, err := New(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, engine)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, engine)
				assert.Equal(t, tt.config.FIPSEnabled, engine.IsFIPS())
			}
		})
	}
}

func TestGenerateKeyPair(t *testing.T) {
	keyStore := newMockKeyStore()
	e, err := New(Config{
		FIPSEnabled: true,
		KeyStore:    keyStore,
	})
	require.NoError(t, err)

	tests := []struct {
		name    string
		bits    int
		wantErr bool
	}{
		{
			name:    "2048-bit key (FIPS minimum)",
			bits:    2048,
			wantErr: false,
		},
		{
			name:    "3072-bit key",
			bits:    3072,
			wantErr: false,
		},
		{
			name:    "4096-bit key",
			bits:    4096,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := e.GenerateKeyPair(tt.bits)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, key)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, key)
				assert.Equal(t, tt.bits, key.N.BitLen())

				// Test storing and retrieving the key
				err := e.StoreKey("test-key", key)
				assert.NoError(t, err)

				retrievedKey, err := e.GetKey("test-key")
				assert.NoError(t, err)
				assert.NotNil(t, retrievedKey)
			}
		})
	}

	// Test FIPS key size requirement
	t.Run("1024-bit key (FIPS violation)", func(t *testing.T) {
		e, err := New(Config{
			FIPSEnabled: true,
			KeyStore:    newMockKeyStore(),
		})
		require.NoError(t, err)
		
		key, err := e.GenerateKeyPair(1024)
		assert.Error(t, err)
		assert.Nil(t, key)
	})
}

func TestEncryptDecrypt(t *testing.T) {
	e, err := New(Config{
		FIPSEnabled: true,
		KeyStore:    newMockKeyStore(),
	})
	require.NoError(t, err)

	key, err := e.GenerateKeyPair(2048)
	require.NoError(t, err)

	message := []byte("test message")

	encrypted, err := e.Encrypt(&key.PublicKey, message)
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)

	decrypted, err := e.Decrypt(key, encrypted)
	require.NoError(t, err)
	assert.Equal(t, message, decrypted)
}

func TestSignVerify(t *testing.T) {
	e, err := New(Config{
		FIPSEnabled: true,
		KeyStore:    newMockKeyStore(),
	})
	require.NoError(t, err)

	key, err := e.GenerateKeyPair(2048)
	require.NoError(t, err)

	message := []byte("test message")

	signature, err := e.Sign(key, message)
	require.NoError(t, err)
	assert.NotEmpty(t, signature)

	err = e.Verify(&key.PublicKey, message, signature)
	assert.NoError(t, err)

	// Test with wrong message
	err = e.Verify(&key.PublicKey, []byte("wrong message"), signature)
	assert.Error(t, err)
}

func TestGenerateTLSConfig(t *testing.T) {
	e, err := New(Config{
		FIPSEnabled: true,
		KeyStore:    newMockKeyStore(),
	})
	require.NoError(t, err)

	config := e.GenerateTLSConfig()
	assert.NotNil(t, config)
	assert.Equal(t, uint16(tls.VersionTLS12), config.MinVersion)
	assert.NotEmpty(t, config.CipherSuites)
}

func TestGenerateSelfSignedCert(t *testing.T) {
	e, err := New(Config{
		FIPSEnabled: true,
		KeyStore:    newMockKeyStore(),
	})
	require.NoError(t, err)

	certPEM, keyPEM, err := e.GenerateSelfSignedCert("test.example.com")
	require.NoError(t, err)
	assert.NotEmpty(t, certPEM)
	assert.NotEmpty(t, keyPEM)

	// Verify certificate
	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block)

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	// Verify certificate properties
	assert.Equal(t, "test.example.com", cert.Subject.CommonName)
	assert.Contains(t, cert.DNSNames, "test.example.com")
	assert.True(t, cert.BasicConstraintsValid)
	assert.True(t, cert.KeyUsage&x509.KeyUsageDigitalSignature != 0)
	assert.True(t, cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0)
	assert.Len(t, cert.ExtKeyUsage, 1)
	assert.Equal(t, x509.ExtKeyUsageServerAuth, cert.ExtKeyUsage[0])
}

func TestTLSSetup(t *testing.T) {
	// Create a temporary directory for test files
	tempDir := t.TempDir()
	certFile := filepath.Join(tempDir, "cert.pem")
	keyFile := filepath.Join(tempDir, "key.pem")

	// Create engine with self-signed certificate
	e, err := New(Config{
		FIPSEnabled: true,
		KeyStore:    newMockKeyStore(),
	})
	require.NoError(t, err)

	// Generate and save self-signed certificate
	certPEM, keyPEM, err := e.GenerateSelfSignedCert("localhost")
	require.NoError(t, err)

	err = os.WriteFile(certFile, certPEM, 0644)
	require.NoError(t, err)
	err = os.WriteFile(keyFile, keyPEM, 0600)
	require.NoError(t, err)

	// Create new engine with TLS config
	e, err = New(Config{
		FIPSEnabled: true,
		KeyStore:    newMockKeyStore(),
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
	})
	require.NoError(t, err)

	tlsCfg := e.GetTLSConfig()
	require.NotNil(t, tlsCfg)
	assert.Len(t, tlsCfg.Certificates, 1)
}

func TestFIPSMode(t *testing.T) {
	e, err := New(Config{
		FIPSEnabled: true,
		KeyStore:    newMockKeyStore(),
	})
	require.NoError(t, err)

	// Should fail with key size < 2048 bits in FIPS mode
	_, err = e.GenerateKeyPair(1024)
	assert.Error(t, err)

	// Create a non-FIPS engine
	nonFIPSEngine, err := New(Config{
		FIPSEnabled: false,
		KeyStore:    newMockKeyStore(),
	})
	require.NoError(t, err)

	// Should work in non-FIPS mode
	_, err = nonFIPSEngine.GenerateKeyPair(1024)
	assert.NoError(t, err)
}