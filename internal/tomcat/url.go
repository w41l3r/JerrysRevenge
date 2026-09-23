package tomcat

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// ParseTarget validates a URL without making a network request.
func ParseTarget(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(strings.TrimPrefix(raw, "\ufeff"))
	if raw == "" {
		return nil, fmt.Errorf("empty URL")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid URL syntax")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("scheme must be http or https")
	}
	if u.Host == "" {
		return nil, fmt.Errorf("missing host")
	}
	if u.User != nil {
		return nil, fmt.Errorf("URL userinfo is not allowed; keep credentials separate")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("query strings and fragments are not allowed in the base URL")
	}
	if strings.Contains(u.EscapedPath(), ";") {
		return nil, fmt.Errorf("path parameters are not allowed in the base URL")
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u, nil
}

// LoadTargets reads one URL per non-empty, non-comment line.
func LoadTargets(path string) ([]*url.URL, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open target list: %w", err)
	}
	defer f.Close()

	var targets []*url.URL
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		raw := strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "\ufeff"))
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		u, err := ParseTarget(raw)
		if err != nil {
			return nil, fmt.Errorf("target list line %d: %w", line, err)
		}
		key := u.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		targets = append(targets, u)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read target list: %w", err)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("target list contains no valid URLs")
	}
	return targets, nil
}

// BuildEndpoint appends a raw path suffix without path cleaning. This is
// intentional: cleaning would destroy the semicolon/dot-segment test cases.
func BuildEndpoint(base *url.URL, suffix string) (string, error) {
	u := *base
	rawPrefix := strings.TrimRight(base.EscapedPath(), "/")
	if rawPrefix == "" {
		rawPrefix = ""
	}
	if suffix != "" && !strings.HasPrefix(suffix, "/") {
		return "", fmt.Errorf("suffix must start with a slash")
	}
	rawPath := rawPrefix + suffix
	if rawPath == "" {
		rawPath = "/"
	}
	decoded, err := url.PathUnescape(rawPath)
	if err != nil {
		return "", fmt.Errorf("decode path: %w", err)
	}
	u.Path = decoded
	u.RawPath = rawPath
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

func bypassPaths() []string {
	return []string{
		"/jr/..;" + managerPath,
		"/;a=b" + managerPath,
	}
}
