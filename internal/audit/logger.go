// Copyright 2025 copyleftdev. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/golang/glog"
)

// EventType represents the type of audit event.
type EventType string

// Standard audit event types.
const (
	EventKeyGen     EventType = "key_generate"
	EventKeyStore   EventType = "key_store"
	EventKeyRetrieve EventType = "key_retrieve"
	EventKeyDelete  EventType = "key_delete"
	EventCryptoOp   EventType = "crypto_operation"
	EventAuth       EventType = "authentication"
	EventConfig     EventType = "configuration"
)

// Event represents an audit log entry.
type Event struct {
	Timestamp  time.Time         `json:"timestamp"`
	EventType EventType         `json:"event_type"`
	Subject   string            `json:"subject,omitempty"`
	Resource  string            `json:"resource,omitempty"`
	Action    string            `json:"action"`
	Status    string            `json:"status"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	Signature string            `json:"signature,omitempty"`
}

// Logger provides secure audit logging capabilities.
type Logger struct {
	writer   io.Writer
	key      []byte
	mu       sync.Mutex
	enabled  bool
	hmacAlgo func() hash.Hash
}

// Config holds configuration for the audit logger.
type Config struct {
	// Required: Path to the audit log file. If empty, logs will be discarded.
	LogPath string

	// Required: HMAC key for log verification. Must be at least 32 bytes.
	HMACKey []byte

	// Optional: Whether audit logging is enabled. Defaults to true.
	Enabled *bool
}

// New creates a new audit logger instance.
func New(config Config) (*Logger, error) {
	if len(config.HMACKey) < 32 {
		return nil, fmt.Errorf("HMAC key must be at least 32 bytes")
	}

	var writer io.Writer = io.Discard
	enabled := true
	if config.Enabled != nil {
		enabled = *config.Enabled
	}

	if enabled && config.LogPath != "" {
		// Ensure the directory exists
		if err := os.MkdirAll(filepath.Dir(config.LogPath), 0700); err != nil {
			return nil, fmt.Errorf("failed to create audit log directory: %w", err)
		}

		// Open the log file in append mode, create if not exists
		f, err := os.OpenFile(config.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return nil, fmt.Errorf("failed to open audit log file: %w", err)
		}

		writer = f
	}

	return &Logger{
		writer:   writer,
		key:      config.HMACKey,
		enabled:  enabled,
		hmacAlgo: sha256.New,
	}, nil
}

// Log records an audit event.
func (l *Logger) Log(event Event) error {
	if !l.enabled {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	event.Timestamp = time.Now().UTC()

	// Convert event to JSON
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal audit event: %w", err)
	}

	// Calculate HMAC signature
	hmac := hmac.New(l.hmacAlgo, l.key)
	if _, err := hmac.Write(data); err != nil {
		return fmt.Errorf("failed to calculate HMAC: %w", err)
	}

	signature := hex.EncodeToString(hmac.Sum(nil))
	event.Signature = signature

	// Re-marshal with signature
	data, err = json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal signed audit event: %w", err)
	}

	// Write to log with newline
	if _, err := fmt.Fprintf(l.writer, "%s\n", data); err != nil {
		return fmt.Errorf("failed to write audit log: %w", err)
	}

	// For critical events, also log to glog
	if isCriticalEvent(event.EventType) {
		glog.Warningf("AUDIT: %s %s %s", event.EventType, event.Action, event.Status)
	}

	return nil
}

// Verify checks the integrity of an audit log entry.
func (l *Logger) Verify(data []byte) (Event, error) {
	var event Event
	if err := json.Unmarshal(data, &event); err != nil {
		return Event{}, fmt.Errorf("invalid audit log entry: %w", err)
	}

	// Save and remove the signature
	signature := event.Signature
	event.Signature = ""

	// Re-marshal without signature
	data, err := json.Marshal(event)
	if err != nil {
		return Event{}, fmt.Errorf("failed to re-marshal event: %w", err)
	}

	// Calculate expected HMAC
	h := hmac.New(l.hmacAlgo, l.key)
	if _, err := h.Write(data); err != nil {
		return Event{}, fmt.Errorf("failed to calculate HMAC: %w", err)
	}

	expectedSignature := hex.EncodeToString(h.Sum(nil))
	if !hmac.Equal([]byte(signature), []byte(expectedSignature)) {
		return Event{}, fmt.Errorf("invalid HMAC signature")
	}

	return event, nil
}

// Close releases any resources used by the logger.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if closer, ok := l.writer.(io.Closer); ok && l.writer != nil {
		return closer.Close()
	}
	return nil
}

// isCriticalEvent returns true if the event type is considered critical.
func isCriticalEvent(eventType EventType) bool {
	switch eventType {
	case EventKeyGen, EventKeyDelete, EventAuth, EventConfig:
		return true
	default:
		return false
	}
}
