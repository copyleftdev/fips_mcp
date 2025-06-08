// Copyright 2025 copyleftdev. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.


package engine

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"

	"github.com/golang/glog"
)

// Engine represents a FIPS 140-3 compliant cryptographic engine.
type Engine struct {
	once     sync.Once
	isFIPS   bool
	tlsCfg   *tls.Config
	rng      io.Reader
	keyStore KeyStore
}

// KeyStore defines the interface for secure key storage.
type KeyStore interface {
	GetKey(id string) (crypto.PrivateKey, error)
	StoreKey(id string, key crypto.PrivateKey) error
	DeleteKey(id string) error
}

// Config holds configuration for the crypto engine.
type Config struct {
	// FIPSEnabled enables FIPS 140-3 compliance mode.
	FIPSEnabled bool

	// TLSCertFile is the path to the TLS certificate file.
	TLSCertFile string

	// TLSKeyFile is the path to the TLS private key file.
	TLSKeyFile string

	// KeyStore is the secure key storage implementation.
	KeyStore KeyStore
}

// New creates a new FIPS 140-3 compliant crypto engine.
func New(cfg Config) (*Engine, error) {
	if cfg.KeyStore == nil {
		return nil, errors.New("key store is required")
	}

	e := &Engine{
		isFIPS:   cfg.FIPSEnabled,
		rng:      rand.Reader,
		keyStore: cfg.KeyStore,
	}

	// Initialize FIPS mode if enabled
	if cfg.FIPSEnabled {
		if err := e.initFIPSMode(); err != nil {
			return nil, fmt.Errorf("failed to initialize FIPS mode: %w", err)
		}
	}

	// Set up TLS configuration if cert and key are provided
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}

		e.tlsCfg = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		}

		// Configure FIPS-compliant cipher suites if in FIPS mode
		if e.isFIPS {
			e.tlsCfg.CipherSuites = []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			}
		}
	}

	return e, nil
}

// initFIPSMode initializes the crypto engine in FIPS 140-3 mode.
func (e *Engine) initFIPSMode() error {
	var err error
	e.once.Do(func() {
		// In a real implementation, this would perform FIPS 140-3 specific
		// initialization, such as:
		// 1. Verifying the FIPS module is properly loaded
		// 2. Running self-tests
		// 3. Configuring FIPS-approved algorithms

		glog.Info("FIPS 140-3 mode initialized")
	})

	return err
}

// IsFIPS returns true if the engine is running in FIPS 140-3 mode.
func (e *Engine) IsFIPS() bool {
	return e.isFIPS
}

// GetTLSConfig returns the configured TLS configuration.
func (e *Engine) GetTLSConfig() *tls.Config {
	return e.tlsCfg
}

// GenerateKeyPair generates a new RSA key pair with the specified bit size.
func (e *Engine) GenerateKeyPair(bits int) (*rsa.PrivateKey, error) {
	if e.isFIPS && bits < 2048 {
		return nil, errors.New("FIPS 140-3 requires at least 2048-bit RSA keys")
	}

	return rsa.GenerateKey(e.rng, bits)
}

// StoreKey stores a private key in the secure key store.
func (e *Engine) StoreKey(id string, key crypto.PrivateKey) error {
	return e.keyStore.StoreKey(id, key)
}

// GetKey retrieves a private key from the secure key store.
func (e *Engine) GetKey(id string) (crypto.PrivateKey, error) {
	return e.keyStore.GetKey(id)
}

// DeleteKey removes a private key from the secure key store.
func (e *Engine) DeleteKey(id string) error {
	return e.keyStore.DeleteKey(id)
}

// Encrypt encrypts data using RSA-OAEP.
func (e *Engine) Encrypt(pubKey *rsa.PublicKey, msg []byte) ([]byte, error) {
	if e.isFIPS && pubKey.Size() < 256 { // 2048-bit key
		return nil, errors.New("FIPS 140-3 requires at least 2048-bit RSA keys")
	}

	return rsa.EncryptOAEP(
		sha256.New(),
		e.rng,
		pubKey,
		msg,
		nil, // label
	)
}

// Decrypt decrypts data using RSA-OAEP.
func (e *Engine) Decrypt(privKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	if e.isFIPS && privKey.Size() < 256 { // 2048-bit key
		return nil, errors.New("FIPS 140-3 requires at least 2048-bit RSA keys")
	}

	return privKey.Decrypt(
		e.rng,
		ciphertext,
		&rsa.OAEPOptions{Hash: crypto.SHA256},
	)
}

// Sign signs data using RSA-PSS.
func (e *Engine) Sign(privKey *rsa.PrivateKey, msg []byte) ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write(msg); err != nil {
		return nil, err
	}
	hash := h.Sum(nil)

	return rsa.SignPSS(
		e.rng,
		privKey,
		crypto.SHA256,
		hash,
		&rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		},
	)
}

// Verify verifies a signature using RSA-PSS.
func (e *Engine) Verify(pubKey *rsa.PublicKey, msg, signature []byte) error {
	h := sha256.New()
	if _, err := h.Write(msg); err != nil {
		return err
	}
	hash := h.Sum(nil)

	return rsa.VerifyPSS(
		pubKey,
		crypto.SHA256,
		hash,
		signature,
		&rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		},
	)
}

// GenerateTLSConfig generates a FIPS-compliant TLS configuration.
func (e *Engine) GenerateTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
}

// GenerateSelfSignedCert generates a self-signed certificate for testing.
func (e *Engine) GenerateSelfSignedCert(commonName string) (certPEM, keyPEM []byte, err error) {
	priv, err := e.GenerateKeyPair(2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	serialNumber, err := rand.Int(e.rng, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"FIPS MCP Test"},
			CommonName:   commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{commonName},
	}

	derBytes, err := x509.CreateCertificate(e.rng, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	return certPEM, keyPEM, nil
}