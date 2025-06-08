// Copyright 2025 copyleftdev. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package audit

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogger(t *testing.T) {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "audit.log")

	// Generate a random HMAC key
	hmacKey := make([]byte, 32)
	_, err := rand.Read(hmacKey)
	require.NoError(t, err)

	// Create a new logger
	logger, err := New(Config{
		LogPath: logPath,
		HMACKey: hmacKey,
	})
	require.NoError(t, err)
	defer logger.Close()

	// Test logging an event
	t.Run("Log and Verify Event", func(t *testing.T) {
		event := Event{
			EventType: EventKeyGen,
			Subject:   "test-user",
			Action:    "generate_key",
			Status:    "success",
			Metadata: map[string]string{
				"key_size": "2048",
				"key_type": "RSA",
			},
		}

		err := logger.Log(event)
		require.NoError(t, err)

		// Read the log file
		data, err := os.ReadFile(logPath)
		require.NoError(t, err)

		require.NotEmpty(t, data)

		// Verify the log entry
		loggedEvent, err := logger.Verify(data[:len(data)-1]) // Remove newline
		require.NoError(t, err)

		assert.Equal(t, event.EventType, loggedEvent.EventType)
		assert.Equal(t, event.Subject, loggedEvent.Subject)
		assert.Equal(t, event.Action, loggedEvent.Action)
		assert.Equal(t, event.Status, loggedEvent.Status)
		assert.Equal(t, event.Metadata["key_size"], loggedEvent.Metadata["key_size"])
		assert.Equal(t, event.Metadata["key_type"], loggedEvent.Metadata["key_type"])
		assert.False(t, loggedEvent.Timestamp.IsZero())
	})

	// Test verification with invalid HMAC
	t.Run("Verify Invalid HMAC", func(t *testing.T) {
		// Create a new logger with a different HMAC key
		badKey := make([]byte, 32)
		_, err := rand.Read(badKey)
		require.NoError(t, err)

		badLogger, err := New(Config{
			LogPath: filepath.Join(tempDir, "bad.log"),
			HMACKey: badKey,
		})
		require.NoError(t, err)
		defer badLogger.Close()

		// Try to verify with the wrong key
		data, err := os.ReadFile(logPath)
		require.NoError(t, err)

		_, err = badLogger.Verify(data[:len(data)-1])
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid HMAC signature")
	})

	// Test disabled logging
	t.Run("Disabled Logging", func(t *testing.T) {
		disabledLogger, err := New(Config{
			LogPath: filepath.Join(tempDir, "disabled.log"),
			HMACKey: hmacKey,
			Enabled: new(bool), // false by default
		})
		require.NoError(t, err)
		defer disabledLogger.Close()

		event := Event{
			EventType: EventKeyGen,
			Action:    "test_disabled",
			Status:    "success",
		}

		err = disabledLogger.Log(event)
		require.NoError(t, err)

		// Verify no log file was created
		_, err = os.Stat(filepath.Join(tempDir, "disabled.log"))
		assert.True(t, os.IsNotExist(err))
	})
}

func TestLogger_ConcurrentAccess(t *testing.T) {
	tempDir := t.TempDir()
	_ = filepath.Join(tempDir, "concurrent.log") // Keep for future use

	// Generate a random HMAC key
	hmacKey := make([]byte, 32)
	_, err := rand.Read(hmacKey)
	require.NoError(t, err)

	// Create a new logger with a buffer for testing
	buf := &bytes.Buffer{}
	logger := &Logger{
		writer:  buf,
		key:     hmacKey,
		enabled: true,
		hmacAlgo: func() hash.Hash {
			return hmac.New(sha256.New, hmacKey)
		},
	}

	// Number of concurrent operations
	count := 10
	done := make(chan struct{}, count)

	// Run concurrent log operations
	for i := 0; i < count; i++ {
		go func(id int) {
			event := Event{
				EventType: EventCryptoOp,
				Subject:   fmt.Sprintf("user-%d", id),
				Action:    "encrypt",
				Status:    "success",
				Metadata: map[string]string{
					"operation_id": fmt.Sprintf("op-%d", id),
				},
			}

			// Add some jitter
			time.Sleep(time.Duration(id%10) * time.Millisecond)
			err := logger.Log(event)
			require.NoError(t, err)
			done <- struct{}{}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < count; i++ {
		<-done
	}

	// Verify all events were logged
	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	assert.Len(t, lines, count)

	// Verify each event
	for i, line := range lines {
		event, err := logger.Verify(line)
		assert.NoError(t, err, "Failed to verify event %d: %s", i, line)
		assert.Equal(t, EventCryptoOp, event.EventType)
		assert.Equal(t, "encrypt", event.Action)
		assert.Equal(t, "success", event.Status)
	}
}

func TestLogger_ErrorCases(t *testing.T) {
	tempDir := t.TempDir()

	// Test with invalid HMAC key
	t.Run("Invalid HMAC Key", func(t *testing.T) {
		_, err := New(Config{
			LogPath: filepath.Join(tempDir, "test.log"),
			HMACKey: []byte("too-short"),
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "HMAC key must be at least 32 bytes")
	})

	// Test with log directory that can't be created
	t.Run("Invalid Log Directory", func(t *testing.T) {
		// Create a directory that we can't write to
		readOnlyDir := filepath.Join(tempDir, "readonly")
		err := os.Mkdir(readOnlyDir, 0444) // Read-only permissions
		require.NoError(t, err)

		// Try to create a log file in the read-only directory
		invalidPath := filepath.Join(readOnlyDir, "audit.log")
		_, err = New(Config{
			LogPath: invalidPath,
			HMACKey: make([]byte, 32),
		})
		assert.Error(t, err)
	})
}
