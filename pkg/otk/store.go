package otk

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"time"

	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

// DefaultTTL is the default time-to-live for one-time keys
const DefaultTTL = 5 * time.Minute

// DefaultKeyLength is the default length of generated keys (40 characters)
const DefaultKeyLength = 40

// ErrKeyNotFound is returned when a key is not found or has expired
var ErrKeyNotFound = errors.New("one-time key not found or expired")

// ErrKeyAlreadyUsed is returned when a key has already been consumed
var ErrKeyAlreadyUsed = errors.New("one-time key already used")

// Store defines the interface for one-time key storage
type Store interface {
	// Save stores a session with a one-time key
	Save(ctx context.Context, key string, session *sessionsapi.SessionState, ttl time.Duration) error
	// Load retrieves and consumes a session by its one-time key (one-time use)
	Load(ctx context.Context, key string) (*sessionsapi.SessionState, error)
	// Delete removes a key from the store
	Delete(ctx context.Context, key string) error
}

// alphanumeric contains only letters and digits (no special characters)
const alphanumeric = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// GenerateKey generates a cryptographically secure random key
// The key contains only alphanumeric characters (0-9, A-Z, a-z)
func GenerateKey(keyLength int) (string, error) {
	b := make([]byte, keyLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	// Map random bytes to alphanumeric characters
	result := make([]byte, keyLength)
	for i := 0; i < keyLength; i++ {
		result[i] = alphanumeric[int(b[i])%len(alphanumeric)]
	}

	return string(result), nil
}

// entry holds a session and its expiration time
type entry struct {
	session   *sessionsapi.SessionState
	expiresAt time.Time
}

// MemoryStore is an in-memory implementation of Store
type MemoryStore struct {
	data   sync.Map
	mu     sync.Mutex
	stopGC chan struct{}
	gcOnce sync.Once
}

// NewMemoryStore creates a new in-memory store with automatic cleanup
func NewMemoryStore() *MemoryStore {
	store := &MemoryStore{
		stopGC: make(chan struct{}),
	}
	// Start garbage collection goroutine
	go store.startGC()
	return store
}

// startGC periodically cleans up expired entries
func (s *MemoryStore) startGC() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			s.data.Range(func(key, value interface{}) bool {
				if e, ok := value.(*entry); ok {
					if now.After(e.expiresAt) {
						s.data.Delete(key)
					}
				}
				return true
			})
		case <-s.stopGC:
			return
		}
	}
}

// Stop stops the garbage collection goroutine
func (s *MemoryStore) Stop() {
	s.gcOnce.Do(func() {
		close(s.stopGC)
	})
}

// Save stores a session with a one-time key
func (s *MemoryStore) Save(ctx context.Context, key string, session *sessionsapi.SessionState, ttl time.Duration) error {
	s.data.Store(key, &entry{
		session:   session,
		expiresAt: time.Now().Add(ttl),
	})
	return nil
}

// Load retrieves and consumes a session by its one-time key
// The key is deleted after a successful load (one-time use)
func (s *MemoryStore) Load(ctx context.Context, key string) (*sessionsapi.SessionState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	value, ok := s.data.LoadAndDelete(key)
	if !ok {
		return nil, ErrKeyNotFound
	}

	e, ok := value.(*entry)
	if !ok {
		return nil, ErrKeyNotFound
	}

	// Check if expired
	if time.Now().After(e.expiresAt) {
		return nil, ErrKeyNotFound
	}

	return e.session, nil
}

// Delete removes a key from the store
func (s *MemoryStore) Delete(ctx context.Context, key string) error {
	s.data.Delete(key)
	return nil
}
