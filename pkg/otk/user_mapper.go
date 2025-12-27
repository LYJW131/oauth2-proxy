package otk

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// UserMapper manages user mapping from sub (OIDC subject) to user data using SQLite
type UserMapper struct {
	mu          sync.Mutex
	db          *sql.DB
	filePath    string
	lastModTime time.Time
}

// ErrUserNotFound is returned when the user is not found in the mapping
var ErrUserNotFound = errors.New("user not found in mapping")

// ErrUserAlreadyExists is returned when trying to add a user that already exists
var ErrUserAlreadyExists = errors.New("user already exists in mapping")

// NewUserMapper creates a new UserMapper using a SQLite database file
func NewUserMapper(filePath string) (*UserMapper, error) {
	mapper := &UserMapper{
		filePath: filePath,
	}

	if err := mapper.reload(); err != nil {
		return nil, err
	}

	return mapper, nil
}

// reload opens or re-opens the database connection
func (m *UserMapper) reload() error {
	// If there's an existing connection, close it
	if m.db != nil {
		m.db.Close()
		m.db = nil
	}

	// If file doesn't exist, we'll create it on sql.Open
	db, err := sql.Open("sqlite", m.filePath)
	if err != nil {
		return fmt.Errorf("failed to open database: %v", err)
	}

	m.db = db

	if err := m.initSchema(); err != nil {
		db.Close()
		m.db = nil
		return err
	}

	if info, err := os.Stat(m.filePath); err == nil {
		m.lastModTime = info.ModTime()
	}

	return nil
}

// refresh checks if the file has been deleted or modified externally
func (m *UserMapper) refresh() {
	m.mu.Lock()
	defer m.mu.Unlock()

	info, err := os.Stat(m.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			// File is gone! Close the connection to stop using "cached" unlinked file
			if m.db != nil {
				m.db.Close()
				m.db = nil
				m.lastModTime = time.Time{}
			}
		}
		return
	}

	// If file was modified or restored after deletion
	if m.db == nil || info.ModTime().After(m.lastModTime) {
		_ = m.reload()
	}
}

func (m *UserMapper) initSchema() error {
	query := `
	CREATE TABLE IF NOT EXISTS users (
		sub TEXT PRIMARY KEY,
		data TEXT NOT NULL
	);`
	_, err := m.db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to initialize schema: %v", err)
	}
	return nil
}

// Close closes the database connection
func (m *UserMapper) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.db != nil {
		return m.db.Close()
	}
	return nil
}

// GetUserData looks up user data by sub (OIDC subject)
func (m *UserMapper) GetUserData(sub string) (json.RawMessage, error) {
	m.refresh()

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.db == nil {
		return nil, ErrUserNotFound
	}

	var dataStr string
	query := "SELECT data FROM users WHERE sub = ?"
	err := m.db.QueryRow(query, sub).Scan(&dataStr)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to query user: %v", err)
	}

	return json.RawMessage(dataStr), nil
}

// HasUser checks if a user with the given sub exists in the mapping
func (m *UserMapper) HasUser(sub string) bool {
	m.refresh()

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.db == nil {
		return false
	}

	var exists bool
	query := "SELECT EXISTS(SELECT 1 FROM users WHERE sub = ?)"
	err := m.db.QueryRow(query, sub).Scan(&exists)
	if err != nil {
		return false
	}
	return exists
}

// AddUser adds a new user to the mapping
func (m *UserMapper) AddUser(sub string, data json.RawMessage) error {
	m.refresh()

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.db == nil {
		// If DB was nil because file was missing, reload will have recreated it
		// But in case refresh didn't reload, we try once more
		if err := m.reload(); err != nil {
			return err
		}
	}

	query := "INSERT INTO users (sub, data) VALUES (?, ?)"
	_, err := m.db.Exec(query, sub, string(data))
	if err != nil {
		// Check if it exists manually to return proper error
		var exists bool
		_ = m.db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE sub = ?)", sub).Scan(&exists)
		if exists {
			return ErrUserAlreadyExists
		}
		return fmt.Errorf("failed to add user: %v", err)
	}

	// Update lastModTime after write
	if info, err := os.Stat(m.filePath); err == nil {
		m.lastModTime = info.ModTime()
	}

	return nil
}

// GetSubs returns all sub (subject) identifiers in the user mapping
func (m *UserMapper) GetSubs() ([]string, error) {
	m.refresh()

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.db == nil {
		return nil, nil
	}

	rows, err := m.db.Query("SELECT sub FROM users")
	if err != nil {
		return nil, fmt.Errorf("failed to query subs: %v", err)
	}
	defer rows.Close()

	var subs []string
	for rows.Next() {
		var sub string
		if err := rows.Scan(&sub); err != nil {
			return nil, err
		}
		subs = append(subs, sub)
	}
	return subs, nil
}

// LoadSubsFromMappingFile is a legacy helper for compatibility during initialization
func LoadSubsFromMappingFile(filePath string) ([]string, error) {
	if filePath == "" {
		return nil, nil
	}

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, nil
	}

	db, err := sql.Open("sqlite", filePath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query("SELECT sub FROM users")
	if err != nil {
		return nil, nil
	}
	defer rows.Close()

	var subs []string
	for rows.Next() {
		var sub string
		if err := rows.Scan(&sub); err != nil {
			return nil, err
		}
		subs = append(subs, sub)
	}
	return subs, nil
}
