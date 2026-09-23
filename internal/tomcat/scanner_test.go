package tomcat

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestScanTargetFingerprintsManagerAndBruteForces(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.RequestURI, "/.jerrysrevenge-404-"):
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `<html><title>HTTP Status 404</title><footer>Apache Tomcat/9.0.82</footer></html>`)
		case r.RequestURI == "/docs/":
			fmt.Fprint(w, `<title>Apache Tomcat 9 (9.0.82) - Documentation Index</title>`)
		case r.RequestURI == "/manager/html":
			username, password, ok := r.BasicAuth()
			if ok && username == "tomcat" && password == "correct-horse" {
				fmt.Fprint(w, `<title>Tomcat Web Application Manager</title>`)
				return
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="Tomcat Manager Application"`)
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "401 Unauthorized")
		default:
			fmt.Fprint(w, "application home")
		}
	}))
	defer server.Close()

	target, err := ParseTarget(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	requester := testRequester(t, 1)
	result := ScanTarget(context.Background(), requester, target, ScanOptions{
		Brute:   true,
		Threads: 1,
		Credentials: []Credential{
			{Username: "tomcat", Password: "wrong", Ref: "WORDLIST-000001", Line: 1},
			{Username: "tomcat", Password: "correct-horse", Ref: "WORDLIST-000002", Line: 2},
			{Username: "admin", Password: "unused", Ref: "WORDLIST-000003", Line: 3},
		},
	})

	if !result.Fingerprint.IsTomcat || result.Fingerprint.Classification != Confirmed {
		t.Fatalf("unexpected fingerprint: %+v", result.Fingerprint)
	}
	if result.Fingerprint.Version != "9.0.82" {
		t.Fatalf("version = %q, want 9.0.82", result.Fingerprint.Version)
	}
	if !result.Manager.Present || !result.Manager.AuthRequired {
		t.Fatalf("unexpected manager assessment: %+v", result.Manager)
	}
	if !result.Brute.Executed || len(result.Brute.Findings) != 1 {
		t.Fatalf("unexpected brute result: %+v", result.Brute)
	}
	if result.Brute.Findings[0].Username != "tomcat" || result.Brute.Findings[0].Password != "correct-horse" {
		t.Fatalf("wrong finding identity")
	}
	if !result.Brute.StoppedOnSuccess {
		t.Fatal("expected default stop-on-success")
	}
	if result.Brute.Attempted != 2 {
		t.Fatalf("attempted = %d, want 2", result.Brute.Attempted)
	}
}

func TestTryBypassPreservesRawRequestTargetAndDetectsChangedRouting(t *testing.T) {
	var mu sync.Mutex
	var requestURIs []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestURIs = append(requestURIs, r.RequestURI)
		mu.Unlock()

		switch {
		case r.RequestURI == "/jr/..;/manager/html":
			w.Header().Set("WWW-Authenticate", `Basic realm="Tomcat Manager Application"`)
			w.WriteHeader(http.StatusUnauthorized)
		case r.RequestURI == "/;a=b/manager/html":
			w.WriteHeader(http.StatusNotFound)
		case r.RequestURI == "/docs/":
			fmt.Fprint(w, `<title>Apache Tomcat 10 (10.1.28) - Documentation Index</title>`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	target, err := ParseTarget(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	result := ScanTarget(context.Background(), testRequester(t, 2), target, ScanOptions{
		TryBypass: true,
		Threads:   2,
	})

	if len(result.Manager.Bypasses) != 2 {
		t.Fatalf("bypass count = %d, want 2", len(result.Manager.Bypasses))
	}
	first := result.Manager.Bypasses[0]
	if !first.ReachesManager || !first.ChangedRouting || first.Classification != Confirmed {
		t.Fatalf("unexpected first bypass: %+v", first)
	}
	mu.Lock()
	joined := strings.Join(requestURIs, "\n")
	mu.Unlock()
	if !strings.Contains(joined, "/jr/..;/manager/html") || !strings.Contains(joined, "/;a=b/manager/html") {
		t.Fatalf("raw request targets not preserved:\n%s", joined)
	}
}

func TestTryBypassIsSkippedWithoutTomcatEvidence(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "generic reverse proxy 404")
	}))
	defer server.Close()

	target, err := ParseTarget(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	result := ScanTarget(context.Background(), testRequester(t, 2), target, ScanOptions{
		TryBypass: true,
		Threads:   2,
	})
	if !result.Manager.BypassRequested || result.Manager.BypassSkipReason == "" {
		t.Fatalf("missing bypass skip decision: %+v", result.Manager)
	}
	if len(result.Manager.Bypasses) != 0 {
		t.Fatalf("unexpected bypass probes: %+v", result.Manager.Bypasses)
	}
	if requests.Load() != 4 {
		t.Fatalf("request count = %d, want 4", requests.Load())
	}
}

func TestBruteForceContinueOnSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if ok && ((username == "first" && password == "one") || (username == "second" && password == "two")) {
			fmt.Fprint(w, `<title>Tomcat Web Application Manager</title>`)
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="Tomcat Manager Application"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	credentials := []Credential{
		{Username: "first", Password: "one", Ref: "WORDLIST-000001", Line: 1},
		{Username: "bad", Password: "bad", Ref: "WORDLIST-000002", Line: 2},
		{Username: "second", Password: "two", Ref: "WORDLIST-000003", Line: 3},
	}
	result := BruteForce(context.Background(), testRequester(t, 1), server.URL, credentials, BruteOptions{
		Threads:           1,
		ContinueOnSuccess: true,
	})
	if len(result.Findings) != 2 || result.Attempted != 3 || result.StoppedOnSuccess {
		t.Fatalf("unexpected continue result: %+v", result)
	}
}

func TestBruteForceHonorsGlobalRequesterConcurrency(t *testing.T) {
	var current atomic.Int64
	var maximum atomic.Int64
	requester := testRequester(t, 3)
	requester.client.Transport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		active := current.Add(1)
		defer current.Add(-1)
		for {
			observed := maximum.Load()
			if active <= observed || maximum.CompareAndSwap(observed, active) {
				break
			}
		}
		time.Sleep(15 * time.Millisecond)
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Status:     "401 Unauthorized",
			Header: http.Header{
				"WWW-Authenticate": []string{`Basic realm="Tomcat Manager Application"`},
			},
			Body:    io.NopCloser(strings.NewReader("401 Unauthorized")),
			Request: r,
		}, nil
	})

	credentials := make([]Credential, 12)
	for index := range credentials {
		credentials[index] = Credential{
			Username: fmt.Sprintf("user-%d", index),
			Password: "invalid",
			Ref:      fmt.Sprintf("WORDLIST-%06d", index+1),
			Line:     index + 1,
		}
	}
	result := BruteForce(context.Background(), requester, "http://example.test/manager/html", credentials, BruteOptions{
		Threads:           8,
		ContinueOnSuccess: true,
	})
	if result.Attempted != len(credentials) {
		t.Fatalf("attempted = %d, want %d", result.Attempted, len(credentials))
	}
	if maximum.Load() < 2 {
		t.Fatalf("concurrency was not exercised; max=%d", maximum.Load())
	}
	if maximum.Load() > 3 {
		t.Fatalf("global requester limit exceeded; max=%d", maximum.Load())
	}
}

func TestStaticCanaryDeploymentUsesManagerHTMLAndCleansUp(t *testing.T) {
	const username = "operator"
	const password = "deployment-value"
	artifact, err := BuildDefaultCanary()
	if err != nil {
		t.Fatal(err)
	}
	harness := &managerHTMLHarness{username: username, password: password, artifact: artifact}
	server := httptest.NewServer(harness)
	defer server.Close()

	target, err := ParseTarget(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	result := ScanTarget(context.Background(), testRequester(t, 1), target, ScanOptions{
		Threads:          1,
		DeployCheck:      true,
		DeployCredential: &Credential{Username: username, Password: password, Ref: "DIRECT-TEST"},
		Canary:           artifact,
	})
	if !result.Deployment.Executed || !result.Deployment.Deployed || !result.Deployment.Verified || !result.Deployment.CleanupSucceeded {
		t.Fatalf("unexpected deployment result: %+v", result.Deployment)
	}
	if result.Deployment.Classification != Confirmed {
		t.Fatalf("deployment classification = %s, want CONFIRMED", result.Deployment.Classification)
	}
	if result.Deployment.Interface != "manager-html" || !result.Deployment.SessionEstablished || !result.Deployment.CSRFTokenFound {
		t.Fatalf("unexpected Manager HTML metadata: %+v", result.Deployment)
	}
	if harness.deployed.Load() {
		t.Fatal("static canary remained deployed")
	}
	if !harness.deployBodyMatches.Load() {
		t.Fatal("deployment body was not the validated artifact")
	}
	if harness.textRequests.Load() != 0 {
		t.Fatalf("Manager text interface was unexpectedly requested %d time(s)", harness.textRequests.Load())
	}
	if strings.Contains(result.Deployment.Deploy.URL, "org.apache.catalina.filters.CSRF_NONCE") {
		t.Fatal("sanitized deployment URL leaked the CSRF parameter")
	}
	if result.Deployment.Deploy.UploadedArtifactSHA256 != artifact.SHA256 || !result.Deployment.Deploy.UsedSessionCookies {
		t.Fatalf("missing sanitized upload metadata: %+v", result.Deployment.Deploy)
	}
}

func TestConfirmedBruteFindingFeedsStaticDeployment(t *testing.T) {
	const username = "wordlist-user"
	const password = "wordlist-value"
	artifact, err := BuildDefaultCanary()
	if err != nil {
		t.Fatal(err)
	}
	harness := &managerHTMLHarness{username: username, password: password, artifact: artifact}
	server := httptest.NewServer(harness)
	defer server.Close()

	target, err := ParseTarget(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	result := ScanTarget(context.Background(), testRequester(t, 1), target, ScanOptions{
		Brute:       true,
		Threads:     1,
		DeployCheck: true,
		Canary:      artifact,
		Credentials: []Credential{
			{Username: "wrong", Password: "wrong", Ref: "WORDLIST-000001", Line: 1},
			{Username: username, Password: password, Ref: "WORDLIST-000002", Line: 2},
		},
	})
	if len(result.Brute.Findings) != 1 || result.Brute.Findings[0].Classification != Confirmed {
		t.Fatalf("unexpected brute result: %+v", result.Brute)
	}
	if !result.Deployment.Verified || !result.Deployment.CleanupSucceeded {
		t.Fatalf("confirmed finding was not used for deployment: %+v", result.Deployment)
	}
	if result.Deployment.CredentialRef != result.Brute.Findings[0].ID {
		t.Fatalf("deployment credential ref = %q, want finding ID %q", result.Deployment.CredentialRef, result.Brute.Findings[0].ID)
	}
	if harness.deployed.Load() {
		t.Fatal("static canary remained deployed")
	}
	if harness.textRequests.Load() != 0 {
		t.Fatalf("Manager text interface was unexpectedly requested %d time(s)", harness.textRequests.Load())
	}
}

type managerHTMLHarness struct {
	username          string
	password          string
	artifact          *CanaryArtifact
	mu                sync.Mutex
	sessionSequence   int
	activeSession     string
	activeToken       string
	deployed          atomic.Bool
	deployBodyMatches atomic.Bool
	textRequests      atomic.Int64
}

func (h *managerHTMLHarness) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	user, value, authenticated := r.BasicAuth()
	validCredential := authenticated && user == h.username && value == h.password

	switch {
	case strings.HasPrefix(r.URL.Path, "/manager/text/"):
		h.textRequests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "Manager text must not be used by the HTML deployment workflow")
	case r.URL.Path == "/manager/html":
		if !validCredential {
			w.Header().Set("WWW-Authenticate", "Basic realm=\"Tomcat Manager Application\"")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		session, token := h.newSession()
		http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: session, Path: "/manager", HttpOnly: true})
		writeManagerHTMLPage(w, token, "")
	case r.URL.Path == "/manager/html/upload":
		if !validCredential || r.Method != http.MethodPost || !h.validSessionAndToken(r) {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "403 Access Denied")
			return
		}
		if r.URL.Query().Get("path") != strings.TrimPrefix(h.artifact.ContextPath, "/") {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "FAIL - invalid deployment path")
			return
		}
		reader, err := r.MultipartReader()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "FAIL - invalid multipart body")
			return
		}
		part, err := reader.NextPart()
		if err != nil || part.FormName() != "deployWar" || part.FileName() != strings.TrimPrefix(h.artifact.ContextPath, "/")+".war" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "FAIL - invalid upload field")
			return
		}
		body, err := io.ReadAll(part)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "FAIL - read error")
			return
		}
		archive, zipErr := zip.NewReader(bytes.NewReader(body), int64(len(body)))
		if zipErr != nil || len(archive.File) != 1 || archive.File[0].Name != "index.html" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "FAIL - invalid WAR")
			return
		}
		h.deployBodyMatches.Store(bytes.Equal(body, h.artifact.Bytes))
		h.deployed.Store(true)
		_, token := h.currentSession()
		writeManagerHTMLPage(w, token, "OK - Deployed application")
	case r.URL.Path == h.artifact.ContextPath+"/":
		if !h.deployed.Load() {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		fmt.Fprint(w, string(staticCanaryHTML(h.artifact.Token)))
	case r.URL.Path == "/manager/html/undeploy":
		if !validCredential || r.Method != http.MethodPost || !h.validSessionAndToken(r) {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "403 Access Denied")
			return
		}
		if r.URL.Query().Get("path") != h.artifact.ContextPath {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "FAIL - Invalid context path")
			return
		}
		h.deployed.Store(false)
		_, token := h.currentSession()
		writeManagerHTMLPage(w, token, "OK - Undeployed application")
	case r.URL.Path == "/docs/":
		fmt.Fprint(w, "<title>Apache Tomcat 10 (10.1.28) - Documentation Index</title>")
	case strings.HasPrefix(r.URL.Path, "/.jerrysrevenge-404-"):
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "<footer>Apache Tomcat/10.1.28</footer>")
	default:
		fmt.Fprint(w, "application home")
	}
}

func (h *managerHTMLHarness) newSession() (string, string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sessionSequence++
	h.activeSession = fmt.Sprintf("test-session-%d", h.sessionSequence)
	h.activeToken = fmt.Sprintf("%032x", h.sessionSequence)
	return h.activeSession, h.activeToken
}

func (h *managerHTMLHarness) currentSession() (string, string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.activeSession, h.activeToken
}

func (h *managerHTMLHarness) validSessionAndToken(r *http.Request) bool {
	session, token := h.currentSession()
	cookie, err := r.Cookie("JSESSIONID")
	return err == nil && cookie.Value == session && r.URL.Query().Get(csrfParameterName) == token
}

func writeManagerHTMLPage(w http.ResponseWriter, token, message string) {
	fmt.Fprintf(w, `<html><head><title>Tomcat Web Application Manager</title></head><body>%s<form method="post" action="/manager/html/upload?%s=%s"></form></body></html>`, message, csrfParameterName, token)
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (function roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func testRequester(t *testing.T, threads int) *Requester {
	t.Helper()
	requester, err := NewRequester(RequesterConfig{
		Timeout:   2 * time.Second,
		Threads:   threads,
		UserAgent: "JerrysRevenge-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	return requester
}
