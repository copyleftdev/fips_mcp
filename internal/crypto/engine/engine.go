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

	"github.com/copyleftdev/fips-mcp/internal/audit"
	"github.com/golang/glog"
)

// Engine represents a FIPS 140-3 compliant cryptographic engine.
type Engine struct {
	once     sync.Once
	isFIPS   bool
	tlsCfg   *tls.Config
	rng      io.Reader
	keyStore KeyStore
	auditLog *audit.Logger
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

	// KeyStore is the secure key store to use.
	KeyStore KeyStore

	// AuditLog is an optional audit logger for tracking crypto operations.
	// If nil, no audit logging will be performed.
	AuditLog *audit.Logger
}

// New creates a new FIPS 140-3 compliant crypto engine.
func New(cfg Config) (*Engine, error) {
	if cfg.KeyStore == nil {
		return nil, errors.New("key store is required")
	}

	e := &Engine{
		isFIPS:   cfg.FIPSEnabled, // Set FIPS mode based on config
		rng:      rand.Reader,
		keyStore: cfg.KeyStore,
		auditLog: cfg.AuditLog,
	}

	// Log engine initialization
	e.auditCryptoOperation("engine_init", "start", map[string]string{
		"fips_enabled": fmt.Sprintf("%v", cfg.FIPSEnabled),
	})

	// Initialize FIPS mode if enabled
	if cfg.FIPSEnabled {
		if err := e.initFIPSMode(); err != nil {
			e.auditCryptoOperation("engine_init", "failure", map[string]string{
				"error": err.Error(),
			})
			return nil, fmt.Errorf("failed to initialize FIPS mode: %w", err)
		}
	}

	// Set up TLS configuration
	e.tlsCfg = e.GenerateTLSConfig()

	// Load TLS certificate if provided
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		e.auditCryptoOperation("tls_config", "load_cert", map[string]string{
			"cert_file": cfg.TLSCertFile,
			"key_file":  cfg.TLSKeyFile,
		})

		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			e.auditCryptoOperation("tls_config", "load_cert_failure", map[string]string{
				"error": err.Error(),
			})
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		e.tlsCfg.Certificates = []tls.Certificate{cert}

		e.auditCryptoOperation("tls_config", "cert_loaded", map[string]string{
			"cert_subject": cert.Leaf.Subject.String(),
			"cert_issuer":  cert.Leaf.Issuer.String(),
			"cert_expiry":  cert.Leaf.NotAfter.Format(time.RFC3339),
		})
	}

	e.auditCryptoOperation("engine_init", "success", nil)
	return e, nil
}

// initFIPSMode initializes the crypto engine in FIPS 140-3 mode.
func (e *Engine) initFIPSMode() error {
	var initErr error
	e.once.Do(func() {
		e.isFIPS = true
		// Additional FIPS-specific initialization can go here
		glog.Info("FIPS 140-3 mode enabled")
	})
	return initErr
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
	e.auditCryptoOperation("generate_keypair", "start", map[string]string{
		"key_bits": fmt.Sprintf("%d", bits),
	})

	// Enforce FIPS 140-3 key size requirements
	if e.isFIPS && bits < 2048 {
		err := errors.New("FIPS 140-3 requires at least 2048-bit RSA keys")
		e.auditCryptoOperation("generate_keypair", "failure", map[string]string{
			"error": err.Error(),
		})
		return nil, err
	}

	// Enforce minimum key size of 1024 bits for non-FIPS mode
	if bits < 1024 {
		err := errors.New("RSA key size must be at least 1024 bits")
		e.auditCryptoOperation("generate_keypair", "failure", map[string]string{
			"error": err.Error(),
		})
		return nil, err
	}

	key, err := rsa.GenerateKey(e.rng, bits)
	if err != nil {
		e.auditCryptoOperation("generate_keypair", "failure", map[string]string{
			"error": err.Error(),
		})
		return nil, err
	}

	e.auditCryptoOperation("generate_keypair", "success", map[string]string{
		"key_id": fmt.Sprintf("%x", key.PublicKey.N.Bytes()[:8]),
	})

	return key, nil
}

// StoreKey stores a private key in the secure key store.
func (e *Engine) StoreKey(id string, key crypto.PrivateKey) error {
	e.auditCryptoOperation("store_key", "start", map[string]string{
		"key_id": id,
	})

	err := e.keyStore.StoreKey(id, key)
	if err != nil {
		e.auditCryptoOperation("store_key", "failure", map[string]string{
			"key_id": id,
			"error":  err.Error(),
		})
		return err
	}

	e.auditCryptoOperation("store_key", "success", map[string]string{
		"key_id": id,
	})

	return nil
}

// GetKey retrieves a private key from the secure key store.
func (e *Engine) GetKey(id string) (crypto.PrivateKey, error) {
	e.auditCryptoOperation("get_key", "start", map[string]string{
		"key_id": id,
	})

	key, err := e.keyStore.GetKey(id)
	if err != nil {
		e.auditCryptoOperation("get_key", "failure", map[string]string{
			"key_id": id,
			"error":  err.Error(),
		})
		return nil, err
	}

	e.auditCryptoOperation("get_key", "success", map[string]string{
		"key_id": id,
	})

	return key, nil
}

// DeleteKey removes a private key from the secure key store.
func (e *Engine) DeleteKey(id string) error {
	e.auditCryptoOperation("delete_key", "start", map[string]string{
		"key_id": id,
	})

	err := e.keyStore.DeleteKey(id)
	if err != nil {
		e.auditCryptoOperation("delete_key", "failure", map[string]string{
			"key_id": id,
			"error":  err.Error(),
		})
		return err
	}

	e.auditCryptoOperation("delete_key", "success", map[string]string{
		"key_id": id,
	})

	return nil
}

// Encrypt encrypts data using RSA-OAEP.
func (e *Engine) Encrypt(pubKey *rsa.PublicKey, msg []byte) ([]byte, error) {
	e.auditCryptoOperation("encrypt", "start", map[string]string{
		"key_id":   fmt.Sprintf("%x", pubKey.N.Bytes()[:8]),
		"msg_size": fmt.Sprintf("%d", len(msg)),
	})

	hash := sha256.New()
	ciphertext, err := rsa.EncryptOAEP(hash, e.rng, pubKey, msg, nil)
	if err != nil {
		e.auditCryptoOperation("encrypt", "failure", map[string]string{
			"key_id": fmt.Sprintf("%x", pubKey.N.Bytes()[:8]),
			"error":  err.Error(),
		})
		return nil, err
	}

	e.auditCryptoOperation("encrypt", "success", map[string]string{
		"key_id":          fmt.Sprintf("%x", pubKey.N.Bytes()[:8]),
		"ciphertext_size": fmt.Sprintf("%d", len(ciphertext)),
	})

	return ciphertext, nil
}

// Decrypt decrypts data using RSA-OAEP.
func (e *Engine) Decrypt(privKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	e.auditCryptoOperation("decrypt", "start", map[string]string{
		"key_id":          fmt.Sprintf("%x", privKey.PublicKey.N.Bytes()[:8]),
		"ciphertext_size": fmt.Sprintf("%d", len(ciphertext)),
	})

	hash := sha256.New()
	plaintext, err := rsa.DecryptOAEP(hash, e.rng, privKey, ciphertext, nil)
	if err != nil {
		e.auditCryptoOperation("decrypt", "failure", map[string]string{
			"key_id": fmt.Sprintf("%x", privKey.PublicKey.N.Bytes()[:8]),
			"error":  err.Error(),
		})
		return nil, err
	}

	e.auditCryptoOperation("decrypt", "success", map[string]string{
		"key_id":      fmt.Sprintf("%x", privKey.PublicKey.N.Bytes()[:8]),
		"plaintext_size": fmt.Sprintf("%d", len(plaintext)),
	})

	return plaintext, nil
}

// Sign signs data using RSA-PSS.
func (e *Engine) Sign(privKey *rsa.PrivateKey, msg []byte) ([]byte, error) {
	e.auditCryptoOperation("sign", "start", map[string]string{
		"key_id":   fmt.Sprintf("%x", privKey.PublicKey.N.Bytes()[:8]),
		"msg_size": fmt.Sprintf("%d", len(msg)),
	})

	hash := sha256.New()
	if _, err := hash.Write(msg); err != nil {
		err := fmt.Errorf("failed to hash message: %w", err)
		e.auditCryptoOperation("sign", "failure", map[string]string{
			"key_id": fmt.Sprintf("%x", privKey.PublicKey.N.Bytes()[:8]),
			"error":  err.Error(),
		})
		return nil, err
	}
	hashSum := hash.Sum(nil)

	signature, err := rsa.SignPSS(e.rng, privKey, crypto.SHA256, hashSum, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	})

	if err != nil {
		e.auditCryptoOperation("sign", "failure", map[string]string{
			"key_id": fmt.Sprintf("%x", privKey.PublicKey.N.Bytes()[:8]),
			"error":  err.Error(),
		})
		return nil, err
	}

	e.auditCryptoOperation("sign", "success", map[string]string{
		"key_id":          fmt.Sprintf("%x", privKey.PublicKey.N.Bytes()[:8]),
		"signature_size": fmt.Sprintf("%d", len(signature)),
	})

	return signature, nil
}

// Verify verifies a signature using RSA-PSS.
func (e *Engine) Verify(pubKey *rsa.PublicKey, msg, signature []byte) error {
	e.auditCryptoOperation("verify", "start", map[string]string{
		"key_id":          fmt.Sprintf("%x", pubKey.N.Bytes()[:8]),
		"msg_size":        fmt.Sprintf("%d", len(msg)),
		"signature_size":  fmt.Sprintf("%d", len(signature)),
	})

	hash := sha256.New()
	if _, err := hash.Write(msg); err != nil {
		err := fmt.Errorf("failed to hash message: %w", err)
		e.auditCryptoOperation("verify", "failure", map[string]string{
			"key_id": fmt.Sprintf("%x", pubKey.N.Bytes()[:8]),
			"error":  err.Error(),
		})
		return err
	}
	hashSum := hash.Sum(nil)

	err := rsa.VerifyPSS(pubKey, crypto.SHA256, hashSum, signature, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	})

	if err != nil {
		e.auditCryptoOperation("verify", "failure", map[string]string{
			"key_id": fmt.Sprintf("%x", pubKey.N.Bytes()[:8]),
			"error":  err.Error(),
		})
		return err
	}

	e.auditCryptoOperation("verify", "success", map[string]string{
		"key_id": fmt.Sprintf("%x", pubKey.N.Bytes()[:8]),
	})

	return nil
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

// auditCryptoOperation logs a cryptographic operation to the audit log if configured.
func (e *Engine) auditCryptoOperation(action, status string, metadata map[string]string) {
	if e.auditLog == nil {
		return
	}

	if metadata == nil {
		metadata = make(map[string]string)
	}

	event := audit.Event{
		EventType: "crypto_operation",
		Action:    action,
		Status:    status,
		Metadata:  metadata,
	}

	if err := e.auditLog.Log(event); err != nil {
		glog.Warningf("Failed to log audit event: %v", err)
	}
}

// GenerateSelfSignedCert generates a self-signed certificate for testing.
func (e *Engine) GenerateSelfSignedCert(commonName string) (certPEM, keyPEM []byte, err error) {
	e.auditCryptoOperation("generate_cert", "start", map[string]string{
		"common_name": commonName,
	})
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