// Copyright 2025 copyleftdev. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package keystore

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/golang/glog"
)

// SecureFileKeyStore implements a secure file-based key store that encrypts keys at rest.
type SecureFileKeyStore struct {
	baseDir  string
	key      []byte // Master encryption key
	keys     map[string][]byte
	keysLock sync.RWMutex
}

// NewSecureFileKeyStore creates a new secure file-based key store.
// The masterKey is used to encrypt all stored keys. If masterKey is empty,
// a new random key will be generated.
func NewSecureFileKeyStore(baseDir string, masterKey []byte) (*SecureFileKeyStore, error) {
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create key store directory: %w", err)
	}

	// If no master key provided, generate a new one
	if len(masterKey) == 0 {
		masterKey = make([]byte, 32) // 256-bit key for AES-256
		if _, err := io.ReadFull(rand.Reader, masterKey); err != nil {
			return nil, fmt.Errorf("failed to generate master key: %w", err)
		}
	}

	return &SecureFileKeyStore{
		baseDir: baseDir,
		key:     masterKey,
		keys:    make(map[string][]byte),
	}, nil
}

// SaveMasterKey saves the master key to a file for recovery.
// This should be stored securely (e.g., in a HSM or secure key management system).
func (s *SecureFileKeyStore) SaveMasterKey(path string) error {
	return os.WriteFile(path, s.key, 0600)
}

// LoadMasterKey loads a master key from a file.
func LoadMasterKey(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// keyPath returns the filesystem path for a key ID.
func (s *SecureFileKeyStore) keyPath(id string) string {
	// Use a hash of the ID for the filename to avoid filesystem issues
	h := sha256.Sum256([]byte(id))
	return filepath.Join(s.baseDir, hex.EncodeToString(h[:])+".key")
}

// encryptKey encrypts a private key for storage.
func (s *SecureFileKeyStore) encryptKey(key crypto.PrivateKey) ([]byte, error) {
	// Serialize the key
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(key); err != nil {
		return nil, fmt.Errorf("failed to serialize key: %w", err)
	}
	plaintext := buf.Bytes()

	// Generate a random nonce
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Create the cipher
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Encrypt the data
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	// Prepend the nonce to the ciphertext
	result := make([]byte, 0, len(nonce)+len(ciphertext))
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

// decryptKey decrypts a private key from storage.
func (s *SecureFileKeyStore) decryptKey(encrypted []byte) (crypto.PrivateKey, error) {
	if len(encrypted) < 13 { // 12-byte nonce + at least 1 byte of ciphertext
		return nil, errors.New("invalid encrypted key format")
	}

	nonce := encrypted[:12]
	ciphertext := encrypted[12:]

	// Create the cipher
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt the data
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key: %w", err)
	}

	// Decode the key
	var key *rsa.PrivateKey
	buf := bytes.NewBuffer(plaintext)
	dec := gob.NewDecoder(buf)
	if err := dec.Decode(&key); err != nil {
		return nil, fmt.Errorf("failed to deserialize key: %w", err)
	}

	return key, nil
}

// StoreKey stores a private key in the key store.
func (s *SecureFileKeyStore) StoreKey(id string, keyIface crypto.PrivateKey) error {
	// Ensure we're storing an RSA key
	key, ok := keyIface.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("only RSA private keys are supported, got %T", keyIface)
	}
	s.keysLock.Lock()
	defer s.keysLock.Unlock()

	encrypted, err := s.encryptKey(key)
	if err != nil {
		return fmt.Errorf("failed to encrypt key: %w", err)
	}

	path := s.keyPath(id)
	tmpPath := path + ".tmp"

	// Write to a temporary file first
	if err := os.WriteFile(tmpPath, encrypted, 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath) // Clean up temp file on error
		return fmt.Errorf("failed to commit key file: %w", err)
	}

	// Cache the encrypted key in memory
	s.keys[id] = encrypted

	glog.V(2).Infof("Stored key %s at %s", id, path)
	return nil
}

// GetKey retrieves a private key from the key store.
func (s *SecureFileKeyStore) GetKey(id string) (crypto.PrivateKey, error) {
	s.keysLock.RLock()
	encrypted, inMemory := s.keys[id]
	s.keysLock.RUnlock()

	// If not in memory, try to load from disk
	if !inMemory {
		path := s.keyPath(id)
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("key %s not found: %w", id, os.ErrNotExist)
			}
			return nil, fmt.Errorf("failed to read key file: %w", err)
		}

		encrypted = data

		// Cache in memory
		s.keysLock.Lock()
		s.keys[id] = encrypted
		s.keysLock.Unlock()
	}

	// Decrypt the key
	key, err := s.decryptKey(encrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key %s: %w", id, err)
	}

	return key, nil
}

// DeleteKey removes a private key from the key store.
func (s *SecureFileKeyStore) DeleteKey(id string) error {
	s.keysLock.Lock()
	defer s.keysLock.Unlock()

	path := s.keyPath(id)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete key file: %w", err)
	}

	delete(s.keys, id)
	glog.V(2).Infof("Deleted key %s", id)
	return nil
}

// ListKeys returns a list of all key IDs in the key store.
func (s *SecureFileKeyStore) ListKeys() ([]string, error) {
	entries, err := os.ReadDir(s.baseDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read key store directory: %w", err)
	}

	keys := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".key" {
			continue
		}

		// Decode the hex-encoded hash back to the original ID
		// Note: In a real implementation, you'd need to maintain a mapping of hashes to original IDs
		// For simplicity, we're just returning the filenames here
		keys = append(keys, entry.Name()[:len(entry.Name())-4]) // Remove .key extension
	}

	return keys, nil
}

// Close releases any resources used by the key store.
func (s *SecureFileKeyStore) Close() error {
	// Clear the in-memory cache
	s.keysLock.Lock()
	defer s.keysLock.Unlock()

	for k := range s.keys {
		delete(s.keys, k)
	}

	return nil
}
