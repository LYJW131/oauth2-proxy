package otk

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
)

// UserMapping represents the user mapping configuration
type UserMapping struct {
	Users map[string]UserMappingInfo `json:"users"`
}

// UserMappingInfo contains user info for a mapped email
type UserMappingInfo struct {
	UserID   int    `json:"user_id"`
	UserName string `json:"user_name"`
}

// UserMapper manages user mapping from email to user info
type UserMapper struct {
	mu       sync.RWMutex
	users    map[string]UserMappingInfo
	filePath string
}

// ErrUserNotFound is returned when the user is not found in the mapping
var ErrUserNotFound = errors.New("user not found in mapping")

// NewUserMapper creates a new UserMapper from a JSON file
func NewUserMapper(filePath string) (*UserMapper, error) {
	mapper := &UserMapper{
		filePath: filePath,
		users:    make(map[string]UserMappingInfo),
	}

	if err := mapper.Load(); err != nil {
		return nil, err
	}

	return mapper, nil
}

// Load loads the user mapping from the configured file
func (m *UserMapper) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(m.filePath)
	if err != nil {
		return err
	}

	var mapping UserMapping
	if err := json.Unmarshal(data, &mapping); err != nil {
		return err
	}

	m.users = mapping.Users

	return nil
}

// GetUser looks up user info by email
func (m *UserMapper) GetUser(email string) (*UserMappingInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if user, ok := m.users[email]; ok {
		return &user, nil
	}
	return nil, ErrUserNotFound
}

// GetEmails returns all email addresses in the user mapping
func (m *UserMapper) GetEmails() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	emails := make([]string, 0, len(m.users))
	for email := range m.users {
		emails = append(emails, email)
	}
	return emails
}

// LoadEmailsFromMappingFile loads emails from a user mapping JSON file
// This is a standalone function that can be used before UserMapper is fully initialized
func LoadEmailsFromMappingFile(filePath string) ([]string, error) {
	if filePath == "" {
		return nil, nil
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var mapping UserMapping
	if err := json.Unmarshal(data, &mapping); err != nil {
		return nil, err
	}

	emails := make([]string, 0, len(mapping.Users))
	for email := range mapping.Users {
		emails = append(emails, email)
	}
	return emails, nil
}
