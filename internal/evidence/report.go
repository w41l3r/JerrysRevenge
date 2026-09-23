package evidence

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/w41l3r/JerrysRevenge/internal/tomcat"
)

const (
	Executed             = "EXECUTED"
	EvaluatedNotExecuted = "EVALUATED — NOT EXECUTED"
)

var reportPathParameterPattern = regexp.MustCompile(";([A-Za-z0-9._-]+)=([^/;]*)")

type Step struct {
	Timestamp      time.Time
	Objective      string
	Operation      string
	Prerequisites  string
	CapturedOutput string
	Interpretation string
	Limitations    string
	Status         string
	Classification tomcat.Classification
	Dependencies   string
}

type ReportConfig struct {
	Path           string
	RunID          string
	Command        []string
	WorkingDir     string
	Timeout        time.Duration
	Insecure       bool
	UserAgent      string
	ToolVersion    string
	RuntimeVersion string
}

// Reporter writes only sanitized observations. It is safe for concurrent use.
type Reporter struct {
	mu       sync.Mutex
	file     *os.File
	sequence int
	err      error
	config   ReportConfig
	command  string
}

func NewReporter(cfg ReportConfig) (*Reporter, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("report path is empty")
	}
	if err := ensureParent(cfg.Path, 0o750); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(cfg.Path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("report path must not be a symbolic link")
	} else if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect report path: %w", err)
	}
	f, err := os.OpenFile(cfg.Path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, fmt.Errorf("create report (choose another --report path if it already exists): %w", err)
	}
	r := &Reporter{file: f, config: cfg, command: shellCommand(sanitizeCommandArgs(cfg.Command))}
	header := fmt.Sprintf("# Jerry's Revenge — sanitized validation runbook\n\n"+
		"- Run ID: \x60%s\x60\n"+
		"- Started: \x60%s\x60\n"+
		"- Tool: \x60jerrysrevenge %s\x60\n"+
		"- Runtime: \x60%s\x60\n"+
		"- Working directory: \x60%s\x60\n"+
		"- Invoked command: \x60%s\x60\n"+
		"- Evidence policy: response bodies are limited to 1 MiB; credential values, cookies, and raw bodies are not written to this file.\n\n",
		markdownInline(cfg.RunID), time.Now().Format(time.RFC3339Nano), markdownInline(cfg.ToolVersion), markdownInline(cfg.RuntimeVersion), markdownInline(cfg.WorkingDir), markdownInline(r.command))
	if _, err := f.WriteString(header); err != nil {
		f.Close()
		return nil, fmt.Errorf("initialize report: %w", err)
	}
	return r, nil
}

func (r *Reporter) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file == nil {
		return r.err
	}
	if err := r.file.Sync(); err != nil && r.err == nil {
		r.err = err
	}
	if err := r.file.Close(); err != nil && r.err == nil {
		r.err = err
	}
	r.file = nil
	return r.err
}

func (r *Reporter) Err() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

func (r *Reporter) RecordStep(step Step) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil || r.file == nil {
		return
	}
	r.sequence++
	if step.Timestamp.IsZero() {
		step.Timestamp = time.Now()
	}
	if step.Status == "" {
		step.Status = EvaluatedNotExecuted
	}
	if step.Classification == "" {
		step.Classification = tomcat.Unverified
	}

	section := fmt.Sprintf("## Step %04d — %s\n\n"+
		"- Timestamp: \x60%s\x60\n"+
		"- Status: \x60%s\x60\n"+
		"- Classification: \x60%s\x60\n"+
		"- Objective: %s\n"+
		"- Working directory: \x60%s\x60\n"+
		"- Prerequisites: %s\n"+
		"- Dependencies: %s\n\n"+
		"### Exact command or operation\n\n%s\n\n"+
		"### Captured output\n\n%s\n\n"+
		"### Technical interpretation\n\n%s\n\n"+
		"### Limitations, cautions, and likely telemetry\n\n%s\n\n",
		r.sequence, markdownHeading(step.Objective), step.Timestamp.Format(time.RFC3339Nano),
		markdownInline(step.Status), markdownInline(string(step.Classification)), markdownText(step.Objective),
		markdownInline(r.config.WorkingDir), markdownText(orDefault(step.Prerequisites, "none beyond the recorded parameters")),
		markdownText(orDefault(step.Dependencies, "none")), indented(step.Operation), indented(orDefault(step.CapturedOutput, "(no captured output; operation was not executed)")),
		markdownText(step.Interpretation), markdownText(step.Limitations))
	if _, err := r.file.WriteString(section); err != nil {
		r.err = fmt.Errorf("write report: %w", err)
	}
}

func (r *Reporter) RecordProbe(probe tomcat.Probe) {
	status := EvaluatedNotExecuted
	if probe.RequestSent {
		status = Executed
	}
	method := probe.Method
	if method == "" {
		method = http.MethodGet
	}
	auth := ""
	if probe.UsedBasicAuth {
		auth = " --user " + shellQuote("<USERNAME:"+probe.CredentialRef+">:<PASSWORD:"+probe.CredentialRef+">")
	}
	session := ""
	if probe.UsedSessionCookies {
		session = " --cookie " + shellQuote("<MANAGER_SESSION_COOKIE:REDACTED>")
	}
	insecure := ""
	if r.config.Insecure {
		insecure = " --insecure"
	}
	contentType := ""
	if probe.RequestContentType != "" && probe.MultipartField == "" {
		contentType = " --header " + shellQuote("Content-Type: "+probe.RequestContentType)
	}
	upload := ""
	if probe.MultipartField != "" && probe.UploadFilename != "" {
		upload = " --form " + shellQuote(fmt.Sprintf("%s=@<STATIC_CANARY_WAR:sha256=%s>;type=application/octet-stream;filename=%s",
			probe.MultipartField, probe.UploadedArtifactSHA256, probe.UploadFilename))
	} else if probe.RequestBodyBytes > 0 {
		upload = " --upload-file " + shellQuote("<STATIC_CANARY_WAR:sha256="+probe.RequestBodySHA256+">")
	}
	equivalent := "curl --silent --show-error --request " + shellQuote(method) + " --max-time " +
		shellQuote(strconv.FormatFloat(r.config.Timeout.Seconds(), 'f', -1, 64)) +
		" --user-agent " + shellQuote(r.config.UserAgent) + insecure + auth + session + contentType + upload + " " + shellQuote(probe.URL)
	operation := "One internal " + method + " request with no retry, initiated by the command in the report header.\n" +
		"Structurally equivalent reproduction command (not run separately; confidential values use stable placeholders):\n" + equivalent

	var output []string
	if probe.Error != "" {
		output = append(output, "error="+probe.Error)
	}
	if probe.Status != "" {
		output = append(output, "status="+probe.Status)
	}
	if probe.FinalURL != "" {
		output = append(output, "final_url="+probe.FinalURL)
	}
	if probe.Server != "" {
		output = append(output, "Server="+probe.Server)
	}
	if probe.WWWAuthenticate != "" {
		output = append(output, "WWW-Authenticate="+probe.WWWAuthenticate)
	}
	if probe.ContentType != "" {
		output = append(output, "Content-Type="+probe.ContentType)
	}
	if probe.Location != "" {
		output = append(output, "Location="+probe.Location)
	}
	if probe.RequestBodySHA256 != "" {
		output = append(output, fmt.Sprintf("request_body_bytes=%d request_body_sha256=%s", probe.RequestBodyBytes, probe.RequestBodySHA256))
	}
	if probe.RequestContentType != "" {
		output = append(output, "request_content_type="+probe.RequestContentType)
	}
	if probe.UploadedArtifactSHA256 != "" {
		output = append(output, fmt.Sprintf("uploaded_artifact_bytes=%d uploaded_artifact_sha256=%s multipart_field=%s filename=%s",
			probe.UploadedArtifactBytes, probe.UploadedArtifactSHA256, probe.MultipartField, probe.UploadFilename))
	}
	if probe.BodySHA256 != "" {
		output = append(output,
			fmt.Sprintf("body_bytes=%d body_sha256=%s truncated=%t", probe.BodyBytes, probe.BodySHA256, probe.BodyTruncated))
	}
	for _, signal := range probe.Signals {
		output = append(output, "evidence_marker="+signal)
	}
	if len(probe.DetectedVersions) > 0 {
		output = append(output, "detected_versions="+strings.Join(probe.DetectedVersions, ","))
	}
	if !probe.StartedAt.IsZero() {
		output = append(output, "request_started_at="+probe.StartedAt.Format(time.RFC3339Nano))
	}
	if !probe.FinishedAt.IsZero() {
		output = append(output, "request_finished_at="+probe.FinishedAt.Format(time.RFC3339Nano))
	}
	output = append(output, "duration="+probe.Duration.String())

	r.RecordStep(Step{
		Objective:      probe.Objective,
		Operation:      operation,
		Prerequisites:  "authorized target and explicit --execute gate; any authentication source was supplied explicitly by the operator",
		CapturedOutput: strings.Join(output, "\n"),
		Interpretation: "Direct observation. A correlated conclusion is recorded later; an HTTP status alone does not confirm Tomcat, bypass, authentication, or deployment.",
		Limitations:    "The response body is limited to 1 MiB and represented only by a hash and sanitized markers. Cookies, Authorization values, credential values, and uploaded bytes are not persisted. Redirects are recorded but never followed. The request may appear in HTTP, proxy, WAF, authentication, and SIEM logs.",
		Status:         status,
		Classification: tomcat.Unverified,
		Dependencies:   "the main command recorded in the report header",
	})
}

func ensureParent(path string, mode os.FileMode) error {
	parent := filepath.Dir(path)
	if parent == "." || parent == "" {
		return nil
	}
	if err := os.MkdirAll(parent, mode); err != nil {
		return fmt.Errorf("create directory %s: %w", parent, err)
	}
	return nil
}

func shellCommand(args []string) string {
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		quoted = append(quoted, shellQuote(arg))
	}
	return strings.Join(quoted, " ")
}

func sanitizeCommandArgs(args []string) []string {
	result := append([]string(nil), args...)
	redactNext := ""
	for index, arg := range result {
		if redactNext != "" {
			switch redactNext {
			case "url":
				result[index] = sanitizeURLArgument(arg)
			case "username":
				result[index] = "<USERNAME:DIRECT-CLI>"
			case "password":
				result[index] = "<PASSWORD:DIRECT-CLI>"
			}
			redactNext = ""
			continue
		}
		switch arg {
		case "-u", "--url":
			redactNext = "url"
		case "-U", "--username":
			redactNext = "username"
		case "-P", "--password":
			redactNext = "password"
		default:
			switch {
			case strings.HasPrefix(arg, "--url="):
				result[index] = "--url=" + sanitizeURLArgument(strings.TrimPrefix(arg, "--url="))
			case strings.HasPrefix(arg, "-u="):
				result[index] = "-u=" + sanitizeURLArgument(strings.TrimPrefix(arg, "-u="))
			case strings.HasPrefix(arg, "--username="):
				result[index] = "--username=<USERNAME:DIRECT-CLI>"
			case strings.HasPrefix(arg, "-U="):
				result[index] = "-U=<USERNAME:DIRECT-CLI>"
			case strings.HasPrefix(arg, "--password="):
				result[index] = "--password=<PASSWORD:DIRECT-CLI>"
			case strings.HasPrefix(arg, "-P="):
				result[index] = "-P=<PASSWORD:DIRECT-CLI>"
			}
		}
	}
	return result
}

func sanitizeURLArgument(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "[REDACTED_INVALID_URL]"
	}
	if u.User != nil {
		u.User = url.User("REDACTED_USERINFO")
	}
	u.Path = reportPathParameterPattern.ReplaceAllString(u.Path, ";$1=[REDACTED]")
	u.RawPath = ""
	if u.RawQuery != "" {
		u.RawQuery = "REDACTED_QUERY"
	}
	u.Fragment = ""
	return u.String()
}

// Command renders argv with POSIX-shell quoting for an exact, reproducible
// representation in the sanitized report.
func Command(args []string) string {
	return shellCommand(sanitizeCommandArgs(args))
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func indented(value string) string {
	lines := strings.Split(strings.ReplaceAll(value, "\r", ""), "\n")
	for i := range lines {
		lines[i] = "    " + lines[i]
	}
	return strings.Join(lines, "\n")
}

func markdownInline(value string) string {
	value = strings.ReplaceAll(value, "\x60", "'")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	return value
}

func markdownHeading(value string) string {
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	return strings.TrimSpace(value)
}

func markdownText(value string) string {
	if value == "" {
		return "(not applicable)"
	}
	value = strings.ReplaceAll(value, "\r", " ")
	return strings.ReplaceAll(value, "\n", " ")
}

func orDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
