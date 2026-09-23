package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/w41l3r/JerrysRevenge/internal/tomcat"
)

func TestRunRequiresExecuteBeforeSendingTraffic(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		fmt.Fprint(w, "unexpected")
	}))
	defer server.Close()

	temp := t.TempDir()
	stdout := createTestFile(t, filepath.Join(temp, "stdout.txt"))
	stderr := createTestFile(t, filepath.Join(temp, "stderr.txt"))
	defer stdout.Close()
	defer stderr.Close()

	code := run([]string{
		"jerrysrevenge",
		"-u", server.URL,
		"--trybypass",
		"--report", filepath.Join(temp, "plan.md"),
	}, stdout, stderr)
	if code != 0 {
		t.Fatalf("run returned %d", code)
	}
	if requests.Load() != 0 {
		t.Fatalf("planning mode sent %d HTTP requests", requests.Load())
	}
	content, err := os.ReadFile(filepath.Join(temp, "plan.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "EVALUATED — NOT EXECUTED") {
		t.Fatal("planning status missing from report")
	}
}

func TestRunEndToEndSeparatesSanitizedReportAndCredentialInventory(t *testing.T) {
	const secret = "integration-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.RequestURI, "/.jerrysrevenge-404-"):
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `<footer>Apache Tomcat/9.0.82</footer>`)
		case r.RequestURI == "/docs/":
			fmt.Fprint(w, `<title>Apache Tomcat 9 (9.0.82) - Documentation Index</title>`)
		case r.RequestURI == "/manager/html":
			username, password, ok := r.BasicAuth()
			if ok && username == "tomcat" && password == secret {
				fmt.Fprint(w, `<title>Tomcat Web Application Manager</title>`)
				return
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="Tomcat Manager Application"`)
			w.WriteHeader(http.StatusUnauthorized)
		default:
			fmt.Fprint(w, "home")
		}
	}))
	defer server.Close()

	temp := t.TempDir()
	wordlist := filepath.Join(temp, "wordlist.txt")
	if err := os.WriteFile(wordlist, []byte("tomcat:wrong\ntomcat:"+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(temp, "report.md")
	inventoryPath := filepath.Join(temp, "restricted", "credentials.jsonl")
	stdoutPath := filepath.Join(temp, "stdout.txt")
	stderrPath := filepath.Join(temp, "stderr.txt")
	stdout := createTestFile(t, stdoutPath)
	stderr := createTestFile(t, stderrPath)
	defer stdout.Close()
	defer stderr.Close()

	code := run([]string{
		"jerrysrevenge",
		"-u", server.URL,
		"-b",
		"-w", wordlist,
		"-t", "1",
		"--execute",
		"--report", reportPath,
		"--credential-inventory", inventoryPath,
	}, stdout, stderr)
	if code != 0 {
		stderrContent, _ := os.ReadFile(stderrPath)
		t.Fatalf("run returned %d: %s", code, stderrContent)
	}

	stdoutContent, err := os.ReadFile(stdoutPath)
	if err != nil {
		t.Fatal(err)
	}
	reportContent, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	inventoryContent, err := os.ReadFile(inventoryPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stdoutContent), secret) {
		t.Fatal("stdout leaked the password")
	}
	if strings.Contains(string(reportContent), secret) {
		t.Fatal("sanitized report leaked the password")
	}
	if !strings.Contains(string(inventoryContent), secret) {
		t.Fatal("restricted inventory did not retain the full password")
	}
	info, err := os.Stat(inventoryPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("inventory mode = %o, want 600", info.Mode().Perm())
	}
}

func TestDeploymentLimitationsDoNotClaimCapabilityAfterDeniedPreflight(t *testing.T) {
	got := deploymentLimitations(tomcat.DeploymentResult{
		Executed: true,
		Deployed: false,
	})
	if !strings.Contains(got, "No successful deployment was observed") {
		t.Fatalf("unexpected limitations: %q", got)
	}
	if strings.Contains(got, "confirms only deployment") {
		t.Fatalf("limitations falsely claim deployment capability: %q", got)
	}
}

func TestDeploymentLimitationsDescribeCompletedLifecycle(t *testing.T) {
	got := deploymentLimitations(tomcat.DeploymentResult{
		Executed:         true,
		Deployed:         true,
		Verified:         true,
		CleanupAttempted: true,
		CleanupSucceeded: true,
	})
	if !strings.Contains(got, "deployment, retrieval, and removal") {
		t.Fatalf("unexpected limitations: %q", got)
	}
}

func createTestFile(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
