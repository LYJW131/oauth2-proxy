package main

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"unsafe"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/watcher"
)

// UserMap holds information from the authenticated emails file
type UserMap struct {
	usersFile string
	m         unsafe.Pointer
}

// NewUserMap parses the authenticated emails file into a new UserMap
//
// TODO (@NickMeves): Audit usage of `unsafe.Pointer` and potentially refactor
func NewUserMap(usersFile string, done <-chan bool, onUpdate func()) *UserMap {
	um := &UserMap{usersFile: usersFile}
	m := make(map[string]bool)
	atomic.StorePointer(&um.m, unsafe.Pointer(&m)) // #nosec G103
	if usersFile != "" {
		logger.Printf("using authenticated emails file %s", usersFile)
		watcher.WatchFileForUpdates(usersFile, done, func() {
			um.LoadAuthenticatedEmailsFile()
			onUpdate()
		})
		um.LoadAuthenticatedEmailsFile()
	}
	return um
}

// IsValid checks if an email is allowed
func (um *UserMap) IsValid(email string) (result bool) {
	m := *(*map[string]bool)(atomic.LoadPointer(&um.m))
	_, result = m[email]
	return
}

// LoadAuthenticatedEmailsFile loads the authenticated emails file from disk
// and parses the contents as CSV
func (um *UserMap) LoadAuthenticatedEmailsFile() {
	r, err := os.Open(um.usersFile)
	if err != nil {
		logger.Fatalf("failed opening authenticated-emails-file=%q, %s", um.usersFile, err)
	}
	defer func(c io.Closer) {
		cerr := c.Close()
		if cerr != nil {
			logger.Fatalf("Error closing authenticated emails file: %s", cerr)
		}
	}(r)
	csvReader := csv.NewReader(r)
	csvReader.Comma = ','
	csvReader.Comment = '#'
	csvReader.TrimLeadingSpace = true
	records, err := csvReader.ReadAll()
	if err != nil {
		logger.Errorf("error reading authenticated-emails-file=%q, %s", um.usersFile, err)
		return
	}
	updated := make(map[string]bool)
	for _, r := range records {
		address := strings.ToLower(strings.TrimSpace(r[0]))
		updated[address] = true
	}
	atomic.StorePointer(&um.m, unsafe.Pointer(&updated)) // #nosec G103
}

func newValidatorImpl(domains []string, usersFile string, otkUserMappingFile string,
	done <-chan bool, onUpdate func()) func(string) bool {
	validUsers := NewUserMap(usersFile, done, onUpdate)

	// Load emails from OTK user mapping file (these take priority)
	otkEmails := make(map[string]bool)
	if otkUserMappingFile != "" {
		logger.Printf("loading email whitelist from OTK user mapping file: %s", otkUserMappingFile)
		// We import the otk package function inline to avoid circular imports
		// Read the file and parse emails
		if data, err := os.ReadFile(otkUserMappingFile); err == nil {
			var mapping struct {
				Users map[string]interface{} `json:"users"`
			}
			if err := json.Unmarshal(data, &mapping); err == nil {
				for email := range mapping.Users {
					otkEmails[strings.ToLower(email)] = true
					logger.Printf("added OTK email to whitelist: %s", email)
				}
			}
		}
	}

	var allowAll bool
	for i, domain := range domains {
		if domain == "*" {
			allowAll = true
			continue
		}
		domains[i] = strings.ToLower(domain)
	}

	validator := func(email string) (valid bool) {
		if email == "" {
			return
		}
		email = strings.ToLower(email)

		// Priority 1: Check OTK user mapping emails
		if _, ok := otkEmails[email]; ok {
			return true
		}

		// Priority 2: Check domain match
		valid = isEmailValidWithDomains(email, domains)
		if !valid {
			// Priority 3: Check authenticated emails file
			valid = validUsers.IsValid(email)
		}
		if allowAll {
			valid = true
		}
		return valid
	}
	return validator
}

// NewValidator constructs a function to validate email addresses
func NewValidator(domains []string, usersFile string, otkUserMappingFile string) func(string) bool {
	return newValidatorImpl(domains, usersFile, otkUserMappingFile, nil, func() {})
}

// isEmailValidWithDomains checks if the authenticated email is validated against the provided domain
func isEmailValidWithDomains(email string, allowedDomains []string) bool {
	for _, domain := range allowedDomains {
		// allow if the domain is perfect suffix match with the email
		if strings.HasSuffix(email, "@"+domain) {
			return true
		}

		// allow if the domain is prefixed with . or *. and
		// the last element (split on @) has the suffix as the domain
		atoms := strings.Split(email, "@")

		if (strings.HasPrefix(domain, ".") && strings.HasSuffix(atoms[len(atoms)-1], domain)) ||
			(strings.HasPrefix(domain, "*.") && strings.HasSuffix(atoms[len(atoms)-1], domain[1:])) {
			return true
		}
	}

	return false
}
