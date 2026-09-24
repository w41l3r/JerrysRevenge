package tomcat

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"

	"github.com/w41l3r/JerrysRevenge/wordlists"
)

const maxCompanyCredentials = 512

// CandidateSummary describes the locally prepared credential set without
// exposing any candidate values in normal output or the sanitized report.
type CandidateSummary struct {
	BaseSource   string
	BaseCount    int
	CompanyCount int
	CompanyYear  int
	TotalCount   int
}

// LoadWordlist accepts "username:password" (preferred) or two
// whitespace-separated fields. Empty passwords are supported with "user:".
func LoadWordlist(path string) ([]Credential, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open wordlist: %w", err)
	}
	defer f.Close()
	return parseWordlist(f, "WORDLIST")
}

// LoadCredentialCandidates loads either the operator-supplied wordlist or the
// transparent corpus embedded in the binary. A company name, when supplied,
// deterministically adds a bounded set of derived candidates.
func LoadCredentialCandidates(path, company string, year int) ([]Credential, CandidateSummary, error) {
	var (
		base    []Credential
		summary CandidateSummary
		err     error
	)
	if path == "" {
		base, err = parseWordlist(strings.NewReader(wordlists.TomcatCommon), "BUNDLED")
		summary.BaseSource = "bundled wordlists/tomcat-common.txt"
	} else {
		base, err = LoadWordlist(path)
		summary.BaseSource = "operator-supplied wordlist"
	}
	if err != nil {
		return nil, CandidateSummary{}, err
	}
	summary.BaseCount = len(base)

	credentials := append([]Credential(nil), base...)
	seen := make(map[string]struct{}, len(credentials))
	for _, credential := range credentials {
		seen[credential.Username+"\x00"+credential.Password] = struct{}{}
	}
	if strings.TrimSpace(company) != "" {
		summary.CompanyYear = year
		generated, generateErr := GenerateCompanyCredentials(company, year)
		if generateErr != nil {
			return nil, CandidateSummary{}, generateErr
		}
		for _, credential := range generated {
			key := credential.Username + "\x00" + credential.Password
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}
			credentials = append(credentials, credential)
			summary.CompanyCount++
		}
	}
	summary.TotalCount = len(credentials)
	return credentials, summary, nil
}

func parseWordlist(reader io.Reader, refPrefix string) ([]Credential, error) {

	var credentials []Credential
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(reader)
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
			Ref:      fmt.Sprintf("%s-%06d", refPrefix, len(credentials)+1),
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

// GenerateCompanyCredentials returns a deterministic and deliberately bounded
// candidate set. It does not write the company name or generated values to
// normal output; the caller reports counts only.
func GenerateCompanyCredentials(company string, year int) ([]Credential, error) {
	company = strings.TrimSpace(company)
	if company == "" {
		return nil, fmt.Errorf("company name cannot be empty")
	}
	if len([]rune(company)) > 64 {
		return nil, fmt.Errorf("company name cannot exceed 64 characters")
	}
	if year < 1970 || year > 9999 {
		return nil, fmt.Errorf("company credential year is outside the supported range")
	}

	tokens := companyTokens(company)
	if len(tokens) == 0 {
		return nil, fmt.Errorf("company name must contain at least one letter or digit")
	}
	lowerCompact := strings.Join(tokens, "")
	titleParts := make([]string, 0, len(tokens))
	for _, token := range tokens {
		titleParts = append(titleParts, upperFirst(token))
	}
	titleCompact := strings.Join(titleParts, "")
	upperCompact := strings.ToUpper(lowerCompact)
	originalCompact := retainLettersAndDigits(company)

	passwordBases := uniqueNonEmpty([]string{
		lowerCompact,
		titleCompact,
		upperCompact,
		originalCompact,
		leet(lowerCompact),
	})
	yearText := fmt.Sprintf("%d", year)
	previousYear := fmt.Sprintf("%d", year-1)
	suffixes := []string{"", "1", "123", "1234", "!", "@", yearText, previousYear, "@" + yearText, "!" + yearText}
	passwords := make([]string, 0, len(passwordBases)*len(suffixes))
	for _, base := range passwordBases {
		for _, suffix := range suffixes {
			passwords = append(passwords, base+suffix)
		}
	}
	passwords = uniqueNonEmpty(passwords)

	usernames := []string{"tomcat", "admin", "manager", "root", lowerCompact}
	if len(tokens) > 1 {
		usernames = append(usernames, tokens[0])
	}
	usernames = uniqueNonEmpty(usernames)

	credentials := make([]Credential, 0, len(usernames)*len(passwords))
	for _, username := range usernames {
		for _, password := range passwords {
			if len(credentials) >= maxCompanyCredentials {
				return credentials, nil
			}
			credentials = append(credentials, Credential{
				Username: username,
				Password: password,
				Ref:      fmt.Sprintf("COMPANY-%06d", len(credentials)+1),
			})
		}
	}
	return credentials, nil
}

func companyTokens(value string) []string {
	var tokens []string
	var current []rune
	flush := func() {
		if len(current) == 0 {
			return
		}
		tokens = append(tokens, strings.ToLower(string(current)))
		current = current[:0]
	}
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			current = append(current, r)
			continue
		}
		flush()
	}
	flush()
	return tokens
}

func retainLettersAndDigits(value string) string {
	var builder strings.Builder
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func upperFirst(value string) string {
	runes := []rune(strings.ToLower(value))
	if len(runes) > 0 {
		runes[0] = unicode.ToUpper(runes[0])
	}
	return string(runes)
}

func leet(value string) string {
	return strings.Map(func(r rune) rune {
		switch unicode.ToLower(r) {
		case 'a':
			return '4'
		case 'e':
			return '3'
		case 'i':
			return '1'
		case 'o':
			return '0'
		case 's':
			return '5'
		case 't':
			return '7'
		default:
			return r
		}
	}, value)
}

func uniqueNonEmpty(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
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
