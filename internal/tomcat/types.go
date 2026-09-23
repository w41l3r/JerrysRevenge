package tomcat

import (
	"net/http"
	"net/url"
	"time"
)

// Classification is the confidence attached to a material conclusion.
type Classification string

const (
	Confirmed  Classification = "CONFIRMED"
	Inferred   Classification = "INFERRED"
	Potential  Classification = "POTENTIAL"
	Unverified Classification = "UNVERIFIED"
)

const managerPath = "/manager/html"

// Credential is one candidate HTTP Basic credential loaded from a wordlist.
// Password must never be copied into Probe, terminal output, or the sanitized report.
type Credential struct {
	Username string
	Password string
	Ref      string
	Line     int
}

// RequestSpec describes one HTTP request while keeping authentication material
// separate from the observation that is safe to report.
type RequestSpec struct {
	URL                    string
	Objective              string
	CredentialRef          string
	Credential             *Credential
	Method                 string
	Body                   []byte
	ContentType            string
	Cookies                []*http.Cookie
	MultipartField         string
	UploadFilename         string
	UploadedArtifactBytes  int
	UploadedArtifactSHA256 string
}

// Probe is the sanitized observation from one HTTP request.
type Probe struct {
	Objective              string
	Method                 string
	URL                    string
	FinalURL               string
	CredentialRef          string
	UsedBasicAuth          bool
	UsedSessionCookies     bool
	RequestSent            bool
	StartedAt              time.Time
	FinishedAt             time.Time
	Duration               time.Duration
	StatusCode             int
	Status                 string
	Server                 string
	WWWAuthenticate        string
	ContentType            string
	Location               string
	BodyBytes              int
	BodySHA256             string
	BodyTruncated          bool
	RequestBodyBytes       int
	RequestBodySHA256      string
	RequestContentType     string
	MultipartField         string
	UploadFilename         string
	UploadedArtifactBytes  int
	UploadedArtifactSHA256 string
	Signals                []string
	DetectedVersions       []string
	Error                  string

	body            []byte
	responseCookies []*http.Cookie
}

// FingerprintResult records whether the endpoint can be attributed to Tomcat.
type FingerprintResult struct {
	Classification Classification
	IsTomcat       bool
	Version        string
	Versions       []string
	Evidence       []string
}

// BypassResult captures one semicolon path-parameter variant.
type BypassResult struct {
	Path           string
	Probe          Probe
	ReachesManager bool
	ChangedRouting bool
	Classification Classification
	Interpretation string
}

// ManagerResult captures the direct and optional bypass observations.
type ManagerResult struct {
	Classification   Classification
	Present          bool
	Open             bool
	AuthRequired     bool
	Direct           Probe
	Bypasses         []BypassResult
	BypassRequested  bool
	BypassSkipReason string
	AuthEndpoint     string
	Evidence         []string
}

// CredentialFinding is kept in memory until it is written to the restricted
// credential inventory. Password must never be rendered to normal output.
type CredentialFinding struct {
	ID             string
	Username       string
	Password       string
	CredentialRef  string
	SourceLine     int
	Endpoint       string
	StatusCode     int
	Classification Classification
	Outcome        string
	ObservedAt     time.Time
}

// BruteResult summarizes a credential validation run without exposing secrets.
type BruteResult struct {
	Requested            bool
	Executed             bool
	SkipReason           string
	Endpoint             string
	InvalidControlStatus int
	Attempted            int
	Invalid              int
	Potential            int
	Errors               int
	RateLimited          bool
	StoppedOnSuccess     bool
	Findings             []CredentialFinding
}

// DeploymentResult records a reversible static-canary deployment validation.
// It never contains credential values or the uploaded archive bytes.
type DeploymentResult struct {
	Requested            bool
	Executed             bool
	SkipReason           string
	Interface            string
	CredentialRef        string
	ArtifactSource       string
	ArtifactSHA256       string
	ArtifactSourceSHA256 string
	ContextPath          string
	Marker               string
	Preflight            Probe
	Deploy               Probe
	Verify               Probe
	Refresh              Probe
	Undeploy             Probe
	SessionEstablished   bool
	CSRFTokenFound       bool
	Deployed             bool
	Verified             bool
	CleanupAttempted     bool
	CleanupSucceeded     bool
	Classification       Classification
	Interpretation       string
}

// Result is the complete result for one target.
type Result struct {
	Target      *url.URL
	Probes      []Probe
	Fingerprint FingerprintResult
	Manager     ManagerResult
	Brute       BruteResult
	Deployment  DeploymentResult
}
