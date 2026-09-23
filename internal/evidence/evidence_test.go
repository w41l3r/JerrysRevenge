package evidence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/w41l3r/JerrysRevenge/internal/tomcat"
)

func TestInventoryUses0600AndStoresFullSecretSeparately(t *testing.T) {
	path := filepath.Join(t.TempDir(), "restricted", "credentials.jsonl")
	inventory := NewInventory(path)
	err := inventory.Append(tomcat.CredentialFinding{
		ID:             "CRED-TOMCAT-TEST",
		Username:       "tomcat",
		Password:       "super-secret",
		CredentialRef:  "WORDLIST-000001",
		SourceLine:     1,
		Endpoint:       "https://example.test/manager/html",
		StatusCode:     200,
		Classification: tomcat.Confirmed,
		Outcome:        "test fixture",
		ObservedAt:     time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "super-secret") {
		t.Fatal("restricted inventory did not retain full secret")
	}
}

func TestSanitizedReportNeverReceivesPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.md")
	reporter, err := NewReporter(ReportConfig{
		Path:       path,
		RunID:      "test",
		Command:    []string{"jerrysrevenge", "-u", "https://example.test", "--execute"},
		WorkingDir: "/tmp/test",
		Timeout:    10 * time.Second,
		UserAgent:  "test-agent",
	})
	if err != nil {
		t.Fatal(err)
	}
	reporter.RecordProbe(tomcat.Probe{
		Objective:       "test",
		URL:             "https://example.test/manager/html",
		CredentialRef:   "WORDLIST-000001",
		UsedBasicAuth:   true,
		RequestSent:     true,
		StartedAt:       time.Now(),
		FinishedAt:      time.Now(),
		StatusCode:      200,
		Status:          "200 OK",
		BodySHA256:      strings.Repeat("a", 64),
		WWWAuthenticate: `Basic realm="Tomcat Manager Application"`,
	})
	if err := reporter.Close(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), "super-secret") {
		t.Fatal("sanitized report leaked password")
	}
	if !strings.Contains(string(content), "<PASSWORD:WORDLIST-000001>") {
		t.Fatal("sanitized report did not preserve stable credential placeholder")
	}
}

func TestReporterRedactsSecretsFromRejectedURLArgument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.md")
	reporter, err := NewReporter(ReportConfig{
		Path:       path,
		RunID:      "test",
		Command:    []string{"jerrysrevenge", "-u", "https://alice:secret@example.test/;jsessionid=session-secret?token=sensitive"},
		WorkingDir: "/tmp/test",
		Timeout:    10 * time.Second,
		UserAgent:  "test-agent",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := reporter.Close(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	for _, secret := range []string{"alice", "secret", "sensitive", "session-secret"} {
		if strings.Contains(text, secret) {
			t.Fatalf("report leaked %q from rejected URL", secret)
		}
	}
	if !strings.Contains(text, "REDACTED_USERINFO") || !strings.Contains(text, "REDACTED_QUERY") {
		t.Fatal("report did not preserve stable redaction placeholders")
	}
}

func TestReporterRedactsDirectCredentialArguments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.md")
	reporter, err := NewReporter(ReportConfig{
		Path:  path,
		RunID: "test",
		Command: []string{
			"jerrysrevenge",
			"-u", "https://example.test",
			"-e",
			"-U", "private-operator-name",
			"--password=private-password-value",
		},
		WorkingDir: "/tmp/test",
		Timeout:    10 * time.Second,
		UserAgent:  "test-agent",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := reporter.Close(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	for _, value := range []string{"private-operator-name", "private-password-value"} {
		if strings.Contains(text, value) {
			t.Fatalf("report leaked direct credential component %q", value)
		}
	}
	if !strings.Contains(text, "<USERNAME:DIRECT-CLI>") || !strings.Contains(text, "<PASSWORD:DIRECT-CLI>") {
		t.Fatal("report did not preserve stable direct-credential placeholders")
	}
}

func TestReporterDescribesMultipartUploadWithoutSessionOrCSRFMaterial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.md")
	reporter, err := NewReporter(ReportConfig{
		Path:       path,
		RunID:      "test",
		Command:    []string{"jerrysrevenge", "-u", "https://example.test", "--exploit", "--execute"},
		WorkingDir: "/tmp/test",
		Timeout:    10 * time.Second,
		UserAgent:  "test-agent",
	})
	if err != nil {
		t.Fatal(err)
	}
	reporter.RecordProbe(tomcat.Probe{
		Objective:              "upload test canary",
		Method:                 "POST",
		URL:                    "https://example.test/manager/html/upload?[REDACTED_QUERY]",
		CredentialRef:          "CRED-TEST",
		UsedBasicAuth:          true,
		UsedSessionCookies:     true,
		RequestSent:            true,
		RequestBodyBytes:       512,
		RequestBodySHA256:      strings.Repeat("b", 64),
		RequestContentType:     "multipart/form-data; boundary=report-safe-boundary",
		MultipartField:         "deployWar",
		UploadFilename:         "jr-canary-test.war",
		UploadedArtifactBytes:  310,
		UploadedArtifactSHA256: strings.Repeat("c", 64),
		StartedAt:              time.Now(),
		FinishedAt:             time.Now(),
		StatusCode:             200,
		Status:                 "200 OK",
	})
	if err := reporter.Close(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	if !strings.Contains(text, "<MANAGER_SESSION_COOKIE:REDACTED>") || !strings.Contains(text, "deployWar") || !strings.Contains(text, "jr-canary-test.war") {
		t.Fatal("report omitted sanitized Manager HTML upload structure")
	}
	for _, forbidden := range []string{"session-secret", "csrf-secret", "org.apache.catalina.filters.CSRF_NONCE="} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("report leaked forbidden Manager state %q", forbidden)
		}
	}
}
