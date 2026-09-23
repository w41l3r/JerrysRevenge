package tomcat

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRequesterNeverFollowsRedirects(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/unexpected-follow", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusTeapot)
	}))
	defer server.Close()

	probe := testRequester(t, 1).Do(context.Background(), RequestSpec{
		URL:       server.URL + "/start",
		Objective: "verify exact redirect behavior",
	})
	if probe.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want %d", probe.StatusCode, http.StatusFound)
	}
	if requests.Load() != 1 {
		t.Fatalf("request count = %d, want exactly 1", requests.Load())
	}
	if probe.Location == "" {
		t.Fatal("redirect Location was not retained")
	}
}

func TestRequesterKeepsSessionAndCSRFValuesOutOfSanitizedProbeFields(t *testing.T) {
	const csrfToken = "0123456789abcdef0123456789abcdef"
	const requestCookie = "request-session-secret"
	const responseCookie = "response-session-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("JSESSIONID")
		if err != nil || cookie.Value != requestCookie || r.URL.Query().Get(csrfParameterName) != csrfToken {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: responseCookie, Path: "/manager"})
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	query := url.Values{csrfParameterName: []string{csrfToken}, "path": []string{"/test"}}
	probe := testRequester(t, 1).Do(context.Background(), RequestSpec{
		URL:     server.URL + "/manager/html/upload?" + query.Encode(),
		Cookies: []*http.Cookie{{Name: "JSESSIONID", Value: requestCookie}},
	})
	if probe.StatusCode != http.StatusOK || !probe.UsedSessionCookies {
		t.Fatalf("unexpected request result: status=%d cookies=%t error=%q", probe.StatusCode, probe.UsedSessionCookies, probe.Error)
	}
	for field, value := range map[string]string{"url": probe.URL, "final_url": probe.FinalURL, "error": probe.Error} {
		if strings.Contains(value, csrfToken) || strings.Contains(value, requestCookie) || strings.Contains(value, responseCookie) {
			t.Fatalf("%s leaked session or CSRF material", field)
		}
	}
	if !strings.Contains(probe.URL, "REDACTED_QUERY") || len(probe.responseCookies) != 1 || probe.responseCookies[0].Value != responseCookie {
		t.Fatal("sanitized reporting or private cookie retention did not behave as expected")
	}
}
