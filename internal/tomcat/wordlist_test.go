package tomcat

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadWordlistFormatsAndDeduplicates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wordlist.txt")
	content := "# comment\nadmin:secret:with:colons\ntomcat password\nblank:\nadmin:secret:with:colons\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	credentials, err := LoadWordlist(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials) != 3 {
		t.Fatalf("got %d credentials, want 3", len(credentials))
	}
	if credentials[0].Password != "secret:with:colons" {
		t.Fatalf("colon password was not preserved")
	}
	if credentials[2].Password != "" {
		t.Fatalf("empty password was not preserved")
	}
}

func TestLoadCredentialFileRequiresExactlyOneColonPair(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential.txt")
	if err := os.WriteFile(path, []byte("# comment\noperator:value:with:colons\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	credential, err := LoadCredentialFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if credential.Username != "operator" || credential.Password != "value:with:colons" || credential.Ref != "CREDENTIAL-FILE-000001" {
		t.Fatalf("unexpected credential metadata: %+v", credential)
	}

	if err := os.WriteFile(path, []byte("one:first\ntwo:second\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredentialFile(path); err == nil {
		t.Fatal("multiple credentials were unexpectedly accepted")
	}
}

func TestBundledWordlistContainsRequestedPair(t *testing.T) {
	credentials, summary, err := LoadCredentialCandidates("", "", 2026)
	if err != nil {
		t.Fatal(err)
	}
	if summary.BaseSource != "bundled wordlists/tomcat-common.txt" || summary.TotalCount != len(credentials) {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	if summary.CompanyYear != 0 {
		t.Fatalf("bundled-only summary has a company year: %+v", summary)
	}
	found := false
	for _, credential := range credentials {
		if credential.Username == "tomcat" && credential.Password == "root" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("bundled wordlist is missing the required tomcat/root candidate")
	}
}

func TestCompanyCredentialsAreDeterministicBoundedAndMerged(t *testing.T) {
	first, err := GenerateCompanyCredentials("Acme Corp", 2026)
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateCompanyCredentials("Acme Corp", 2026)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) == 0 || len(first) > maxCompanyCredentials {
		t.Fatalf("generated count = %d", len(first))
	}
	if len(first) != len(second) {
		t.Fatalf("nondeterministic counts: %d and %d", len(first), len(second))
	}
	for index := range first {
		if first[index] != second[index] {
			t.Fatalf("candidate %d is not deterministic", index)
		}
	}

	seen := make(map[string]struct{}, len(first))
	foundYearVariant := false
	for _, credential := range first {
		key := credential.Username + "\x00" + credential.Password
		if _, duplicate := seen[key]; duplicate {
			t.Fatalf("duplicate generated candidate at %s", credential.Ref)
		}
		seen[key] = struct{}{}
		if strings.Contains(strings.ToLower(credential.Password), "acmecorp") && strings.Contains(credential.Password, "2026") {
			foundYearVariant = true
		}
	}
	if !foundYearVariant {
		t.Fatal("expected a company/year password variant")
	}

	credentials, summary, err := LoadCredentialCandidates("", "Acme Corp", 2026)
	if err != nil {
		t.Fatal(err)
	}
	if summary.CompanyCount == 0 || summary.TotalCount != len(credentials) || summary.TotalCount <= summary.BaseCount {
		t.Fatalf("unexpected merged summary: %+v", summary)
	}
	if summary.CompanyYear != 2026 {
		t.Fatalf("company generation year = %d, want 2026", summary.CompanyYear)
	}
}

func TestCompanyCredentialsRejectUnusableName(t *testing.T) {
	for _, value := range []string{"", "---", strings.Repeat("a", 65)} {
		if _, err := GenerateCompanyCredentials(value, 2026); err == nil {
			t.Fatalf("GenerateCompanyCredentials(%q) unexpectedly succeeded", value)
		}
	}
}
