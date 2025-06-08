// Copyright 2025 copyleftdev. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package keystore

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecureFileKeyStore(t *testing.T) {
	tempDir := t.TempDir()
	// Create a subdirectory for the key store
	storeDir := filepath.Join(tempDir, "keystore")

	// Generate a random master key
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err)

	// Create a new key store
	store, err := NewSecureFileKeyStore(storeDir, masterKey)
	require.NoError(t, err)
	defer store.Close()

	// Generate a test key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Test storing and retrieving a key
	t.Run("Store and Get Key", func(t *testing.T) {
		err := store.StoreKey("test-key", key)
		require.NoError(t, err)

		// Verify the key file exists
		keyPath := store.keyPath("test-key")
		_, err = os.Stat(keyPath)
		assert.NoError(t, err, "key file should exist at %s", keyPath)

		// Retrieve the key
		retrievedKey, err := store.GetKey("test-key")
		require.NoError(t, err)
		require.IsType(t, &rsa.PrivateKey{}, retrievedKey)

		// Verify it's the same key
		retrievedRSA := retrievedKey.(*rsa.PrivateKey)
		assert.Equal(t, key.D, retrievedRSA.D)
		assert.Equal(t, key.N, retrievedRSA.N)
	})

	// Test listing keys
	t.Run("List Keys", func(t *testing.T) {
		// Store a second key
		key2, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		err = store.StoreKey("test-key-2", key2)
		require.NoError(t, err)

		keys, err := store.ListKeys()
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(keys), 2) // At least the two we just added
	})

	// Test key deletion
	t.Run("Delete Key", func(t *testing.T) {
		err := store.DeleteKey("test-key")
		require.NoError(t, err)

		// Verify the key is gone
		_, err = store.GetKey("test-key")
		assert.ErrorIs(t, err, os.ErrNotExist)
	})
}

func TestSecureFileKeyStore_Encryption(t *testing.T) {
	tempDir := t.TempDir()

	// Generate a random master key
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err)

	// Create a new key store
	store, err := NewSecureFileKeyStore(tempDir, masterKey)
	require.NoError(t, err)
	defer store.Close()

	// Generate a test key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Store the key
	err = store.StoreKey("test-key", key)
	require.NoError(t, err)

	// Read the encrypted file directly
	keyPath := store.keyPath("test-key")
	encryptedData, err := os.ReadFile(keyPath)
	require.NoError(t, err)

	// Verify the data is encrypted (not a valid PEM or other recognizable format)
	assert.NotContains(t, string(encryptedData), "PRIVATE KEY")
	assert.NotContains(t, string(encryptedData), "RSA")

	// Test with a different master key (should fail to decrypt)
	wrongKey := make([]byte, 32)
	_, err = rand.Read(wrongKey)
	require.NoError(t, err)

	badStore, err := NewSecureFileKeyStore(tempDir, wrongKey)
	require.NoError(t, err)
	defer badStore.Close()

	_, err = badStore.GetKey("test-key")
	assert.Error(t, err)
}

func TestNewSecureFileKeyStore_GenerateKey(t *testing.T) {
	tempDir := t.TempDir()

	// Create a new key store without a master key
	store, err := NewSecureFileKeyStore(tempDir, nil)
	require.NoError(t, err)
	defer store.Close()

	// Verify a master key was generated
	assert.NotEmpty(t, store.key)
	assert.Len(t, store.key, 32) // 256-bit key

	// Save the master key
	keyPath := filepath.Join(tempDir, "master.key")
	err = store.SaveMasterKey(keyPath)
	require.NoError(t, err)

	// Load the master key and create a new store
	loadedKey, err := LoadMasterKey(keyPath)
	require.NoError(t, err)

	newStore, err := NewSecureFileKeyStore(tempDir, loadedKey)
	require.NoError(t, err)
	defer newStore.Close()

	// Verify the keys are the same
	assert.Equal(t, store.key, newStore.key)
}

func TestSecureFileKeyStore_ConcurrentAccess(t *testing.T) {
	tempDir := t.TempDir()

	// Create a new key store
	store, err := NewSecureFileKeyStore(tempDir, nil)
	require.NoError(t, err)
	defer store.Close()

	// Generate a test key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Store the key
	err = store.StoreKey("test-key", key)
	require.NoError(t, err)

	// Test concurrent access
	t.Run("Concurrent Reads", func(t *testing.T) {
		t.Parallel()
		for i := 0; i < 10; i++ {
			retrievedKey, err := store.GetKey("test-key")
			require.NoError(t, err)
			require.NotNil(t, retrievedKey)
		}
	})

	// Test concurrent writes (should be safe due to locking)
	t.Run("Concurrent Writes", func(t *testing.T) {
		t.Parallel()
		for i := 0; i < 5; i++ {
			newKey, keyErr := rsa.GenerateKey(rand.Reader, 2048)
			require.NoError(t, keyErr)
			err := store.StoreKey("concurrent-key", newKey)
			assert.NoError(t, err)
		}
	})
}
