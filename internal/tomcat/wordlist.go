package tomcat

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// LoadWordlist accepts "username:password" (preferred) or two
// whitespace-separated fields. Empty passwords are supported with "user:".
func LoadWordlist(path string) ([]Credential, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open wordlist: %w", err)
	}
	defer f.Close()

	var credentials []Credential
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		raw := strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "\ufeff"))
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}

		var username, password string
		if before, after, ok := strings.Cut(raw, ":"); ok {
			username = strings.TrimSpace(before)
			password = after
		} else {
			fields := strings.Fields(raw)
			if len(fields) != 2 {
				return nil, fmt.Errorf("wordlist line %d: expected username:password", line)
			}
			username, password = fields[0], fields[1]
		}
		if username == "" {
			return nil, fmt.Errorf("wordlist line %d: username is empty", line)
		}

		key := username + "\x00" + password
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		credentials = append(credentials, Credential{
			Username: username,
			Password: password,
			Ref:      fmt.Sprintf("WORDLIST-%06d", len(credentials)+1),
			Line:     line,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read wordlist: %w", err)
	}
	if len(credentials) == 0 {
		return nil, fmt.Errorf("wordlist contains no credential pairs")
	}
	return credentials, nil
}

// LoadCredentialFile reads exactly one non-comment username:password pair.
// Unlike LoadWordlist, whitespace-separated fields are intentionally rejected.
func LoadCredentialFile(path string) (Credential, error) {
	f, err := os.Open(path)
	if err != nil {
		return Credential{}, fmt.Errorf("open credentials file: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	line := 0
	var credential Credential
	found := false
	for scanner.Scan() {
		line++
		raw := strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "\ufeff"))
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		if found {
			return Credential{}, fmt.Errorf("credentials file contains more than one credential pair")
		}
		username, password, ok := strings.Cut(raw, ":")
		if !ok {
			return Credential{}, fmt.Errorf("credentials file line %d: expected username:password", line)
		}
		username = strings.TrimSpace(username)
		if username == "" {
			return Credential{}, fmt.Errorf("credentials file line %d: username is empty", line)
		}
		credential = Credential{
			Username: username,
			Password: password,
			Ref:      "CREDENTIAL-FILE-000001",
			Line:     line,
		}
		found = true
	}
	if err := scanner.Err(); err != nil {
		return Credential{}, fmt.Errorf("read credentials file: %w", err)
	}
	if !found {
		return Credential{}, fmt.Errorf("credentials file contains no credential pair")
	}
	return credential, nil
}
