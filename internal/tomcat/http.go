package tomcat

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const maxBodyBytes int64 = 1024 * 1024

var pathParameterPattern = regexp.MustCompile(`;([A-Za-z0-9._-]+)=([^/;]*)`)

// Observer receives sanitized request observations. It must not receive raw
// credentials or arbitrary response bodies.
type Observer func(Probe)

type RequesterConfig struct {
	Timeout   time.Duration
	Threads   int
	Delay     time.Duration
	Insecure  bool
	UserAgent string
	Observer  Observer
}

// Requester applies a global concurrency limit to all targets and never
// retries requests automatically.
type Requester struct {
	client    *http.Client
	delay     time.Duration
	userAgent string
	sem       chan struct{}
	gateMu    sync.Mutex
	nextStart time.Time
	observer  Observer
}

func NewRequester(cfg RequesterConfig) (*Requester, error) {
	if cfg.Threads < 1 {
		return nil, fmt.Errorf("threads must be greater than zero")
	}
	if cfg.Timeout <= 0 {
		return nil, fmt.Errorf("timeout must be greater than zero")
	}
	if cfg.Delay < 0 {
		return nil, fmt.Errorf("delay cannot be negative")
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Avoid silently expanding scope through environment proxy variables.
	transport.Proxy = nil
	transport.MaxConnsPerHost = cfg.Threads
	transport.MaxIdleConnsPerHost = cfg.Threads
	if cfg.Insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- explicit operator option
	}

	r := &Requester{
		delay:     cfg.Delay,
		userAgent: cfg.UserAgent,
		sem:       make(chan struct{}, cfg.Threads),
		observer:  cfg.Observer,
	}
	r.client = &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return r, nil
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

func (r *Requester) waitForSlot(ctx context.Context) error {
	select {
	case r.sem <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}

	if r.delay == 0 {
		return nil
	}

	r.gateMu.Lock()
	defer r.gateMu.Unlock()
	wait := time.Until(r.nextStart)
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			<-r.sem
			return ctx.Err()
		}
	}
	r.nextStart = time.Now().Add(r.delay)
	return nil
}

func (r *Requester) releaseSlot() {
	<-r.sem
}

// Do executes exactly one GET or PUT request. There are no retries.
func (r *Requester) Do(ctx context.Context, spec RequestSpec) (p Probe) {
	method := spec.Method
	if method == "" {
		method = http.MethodGet
	}
	p = Probe{
		Objective:              spec.Objective,
		Method:                 method,
		URL:                    sanitizeURLString(spec.URL),
		CredentialRef:          spec.CredentialRef,
		UsedBasicAuth:          spec.Credential != nil,
		UsedSessionCookies:     len(spec.Cookies) > 0,
		MultipartField:         spec.MultipartField,
		UploadFilename:         spec.UploadFilename,
		UploadedArtifactBytes:  spec.UploadedArtifactBytes,
		UploadedArtifactSHA256: spec.UploadedArtifactSHA256,
		StartedAt:              time.Now(),
	}
	if len(spec.Body) > 0 {
		sum := sha256.Sum256(spec.Body)
		p.RequestBodyBytes = len(spec.Body)
		p.RequestBodySHA256 = hex.EncodeToString(sum[:])
		p.RequestContentType = sanitizeText(spec.ContentType, 128)
	}
	defer func() {
		p.FinishedAt = time.Now()
		p.Duration = p.FinishedAt.Sub(p.StartedAt)
		if r.observer != nil {
			r.observer(p)
		}
	}()

	if err := r.waitForSlot(ctx); err != nil {
		p.Error = sanitizeText(err.Error(), 512)
		return p
	}
	defer r.releaseSlot()

	if method != http.MethodGet && method != http.MethodPost && method != http.MethodPut {
		p.Error = "unsupported internal HTTP method"
		return p
	}
	if method == http.MethodGet && len(spec.Body) != 0 {
		p.Error = "GET request body is not permitted"
		return p
	}
	var requestBody io.Reader
	if len(spec.Body) > 0 {
		requestBody = bytes.NewReader(spec.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, spec.URL, requestBody)
	if err != nil {
		p.Error = sanitizeText(err.Error(), 512)
		return p
	}
	req.Header.Set("User-Agent", r.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8")
	if spec.ContentType != "" {
		req.Header.Set("Content-Type", spec.ContentType)
	}
	if spec.Credential != nil {
		req.SetBasicAuth(spec.Credential.Username, spec.Credential.Password)
	}
	for _, cookie := range spec.Cookies {
		if cookie == nil {
			continue
		}
		clone := *cookie
		req.AddCookie(&clone)
	}

	p.RequestSent = true
	resp, err := r.client.Do(req)
	if err != nil {
		p.Error = sanitizeHTTPError(err)
		return p
	}
	defer resp.Body.Close()

	p.StatusCode = resp.StatusCode
	p.Status = sanitizeText(resp.Status, 128)
	p.Server = sanitizeText(resp.Header.Get("Server"), 256)
	p.WWWAuthenticate = sanitizeAuthChallenge(resp.Header.Get("WWW-Authenticate"))
	p.ContentType = sanitizeText(resp.Header.Get("Content-Type"), 256)
	p.Location = sanitizeLocation(resp.Header.Get("Location"), resp.Request.URL)
	p.responseCookies = cloneCookies(resp.Cookies())
	if resp.Request != nil && resp.Request.URL != nil {
		p.FinalURL = sanitizedURL(resp.Request.URL)
	}

	responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if readErr != nil {
		p.Error = "read response: " + sanitizeText(readErr.Error(), 384)
	}
	if int64(len(responseBody)) > maxBodyBytes {
		responseBody = responseBody[:maxBodyBytes]
		p.BodyTruncated = true
	}
	p.body = responseBody
	p.BodyBytes = len(responseBody)
	sum := sha256.Sum256(responseBody)
	p.BodySHA256 = hex.EncodeToString(sum[:])
	p.Signals, p.DetectedVersions = extractEvidence(p)
	return p
}

func sanitizeAuthChallenge(raw string) string {
	lower := strings.ToLower(raw)
	switch {
	case strings.Contains(lower, "tomcat host manager application"):
		return `Basic realm="Tomcat Host Manager Application"`
	case strings.Contains(lower, "tomcat manager application"):
		return `Basic realm="Tomcat Manager Application"`
	case strings.HasPrefix(strings.TrimSpace(lower), "basic"):
		return "Basic challenge present; realm and parameters redacted"
	case strings.TrimSpace(raw) != "":
		fields := strings.Fields(raw)
		if len(fields) > 0 {
			return sanitizeText(fields[0], 32) + " challenge present; parameters redacted"
		}
	}
	return ""
}

func sanitizeHTTPError(err error) string {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		requestURL := "[invalid URL]"
		if parsed, parseErr := url.Parse(urlErr.URL); parseErr == nil {
			requestURL = sanitizedURL(parsed)
		}
		return sanitizeText(fmt.Sprintf("%s %s: %v", urlErr.Op, requestURL, urlErr.Err), 512)
	}
	return sanitizeText(err.Error(), 512)
}

func sanitizeLocation(raw string, base *url.URL) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "[invalid Location header]"
	}
	if base != nil {
		u = base.ResolveReference(u)
	}
	return sanitizedURL(u)
}

func sanitizedURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	clone := *u
	clone.User = nil
	clone.Path = pathParameterPattern.ReplaceAllString(clone.Path, `;$1=[REDACTED]`)
	clone.RawPath = ""
	if clone.RawQuery != "" {
		clone.RawQuery = "[REDACTED_QUERY]"
	}
	clone.Fragment = ""
	return clone.String()
}

func sanitizeURLString(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "[invalid URL]"
	}
	return sanitizedURL(u)
}

func cloneCookies(cookies []*http.Cookie) []*http.Cookie {
	result := make([]*http.Cookie, 0, len(cookies))
	for _, cookie := range cookies {
		if cookie == nil {
			continue
		}
		clone := *cookie
		result = append(result, &clone)
	}
	return result
}

func sanitizeText(value string, limit int) string {
	value = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, value)
	value = strings.TrimSpace(value)
	runes := []rune(value)
	if len(runes) > limit {
		return string(runes[:limit]) + "..."
	}
	return value
}
