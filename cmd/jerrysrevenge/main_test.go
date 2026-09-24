package main

import (
	"fmt"
	"net"
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
	var ajpConnections atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		fmt.Fprint(w, "unexpected")
	}))
	defer server.Close()
	ajpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ajpDone := make(chan struct{})
	go func() {
		defer close(ajpDone)
		connection, acceptErr := ajpListener.Accept()
		if acceptErr == nil {
			ajpConnections.Add(1)
			connection.Close()
		}
	}()

	temp := t.TempDir()
	stdout := createTestFile(t, filepath.Join(temp, "stdout.txt"))
	stderr := createTestFile(t, filepath.Join(temp, "stderr.txt"))
	defer stdout.Close()
	defer stderr.Close()

	code := run([]string{
		"jerrysrevenge",
		"-u", server.URL,
		"--trybypass",
		"--ghostcat",
		"--ajp-port", fmt.Sprintf("%d", ajpListener.Addr().(*net.TCPAddr).Port),
		"--ghostcat-output-dir", filepath.Join(temp, "restricted", "ghostcat"),
		"--report", filepath.Join(temp, "plan.md"),
	}, stdout, stderr)
	ajpListener.Close()
	<-ajpDone
	if code != 0 {
		t.Fatalf("run returned %d", code)
	}
	if requests.Load() != 0 {
		t.Fatalf("planning mode sent %d HTTP requests", requests.Load())
	}
	if ajpConnections.Load() != 0 {
		t.Fatalf("planning mode opened %d AJP connections", ajpConnections.Load())
	}
	if _, err := os.Stat(filepath.Join(temp, "restricted", "ghostcat")); !os.IsNotExist(err) {
		t.Fatalf("planning mode created the Ghostcat evidence directory: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(temp, "plan.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "EVALUATED — NOT EXECUTED") {
		t.Fatal("planning status missing from report")
	}
}

func TestRunRejectsGhostcatInputsBeforeHTTP(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		fmt.Fprint(w, "unexpected")
	}))
	defer server.Close()

	temp := t.TempDir()
	unsafeDir := filepath.Join(temp, "unsafe")
	if err := os.Mkdir(unsafeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		extra []string
	}{
		{name: "invalid AJP host", extra: []string{"--ajp-host", "bad/host"}},
		{name: "unsafe evidence directory", extra: []string{"--ghostcat-output-dir", unsafeDir}},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requests.Store(0)
			stdout := createTestFile(t, filepath.Join(temp, fmt.Sprintf("stdout-%d.txt", index)))
			stderr := createTestFile(t, filepath.Join(temp, fmt.Sprintf("stderr-%d.txt", index)))
			defer stdout.Close()
			defer stderr.Close()

			args := []string{
				"jerrysrevenge",
				"--url", server.URL,
				"--ghostcat",
				"--execute",
				"--report", filepath.Join(temp, fmt.Sprintf("report-%d.md", index)),
			}
			args = append(args, test.extra...)
			if code := run(args, stdout, stderr); code != 2 {
				t.Fatalf("run returned %d, want 2", code)
			}
			if got := requests.Load(); got != 0 {
				t.Fatalf("invalid local input caused %d HTTP requests", got)
			}
		})
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
