package tomcat

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

const (
	maxStaticCanaryWARBytes = 64 * 1024
	canaryMarkerPrefix      = "JERRYSREVENGE_STATIC_CANARY:"
)

var canaryTokenPattern = regexp.MustCompile("^[A-Za-z0-9._-]{12,64}$")

// CanaryArtifact is a static, non-executable WAR accepted by the deployment
// validator. Bytes are kept in memory and are never copied into reports.
type CanaryArtifact struct {
	Bytes        []byte
	SHA256       string
	SourceSHA256 string
	Token        string
	Marker       string
	ContextPath  string
	Source       string
}

// BuildDefaultCanary creates a WAR containing only a canonical static
// index.html marker. It has no JSP, class, JAR, script, or deployment descriptor.
func BuildDefaultCanary() (*CanaryArtifact, error) {
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return nil, fmt.Errorf("generate canary token: %w", err)
	}
	token := hex.EncodeToString(random)
	archive, err := buildCanonicalCanaryWAR(token)
	if err != nil {
		return nil, err
	}
	artifact := newCanaryArtifact(archive, token, "built-in static canary")
	artifact.SourceSHA256 = artifact.SHA256
	return artifact, nil
}

// LoadStaticCanaryWAR accepts only the exact one-file static canary profile
// produced by BuildDefaultCanary, then repacks it into a deterministic archive.
// This prevents --war-file from becoming an arbitrary executable WAR upload
// primitive and avoids ZIP-parser differences or trailing source data.
func LoadStaticCanaryWAR(path string) (*CanaryArtifact, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect WAR file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("WAR file must not be a symbolic link")
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("WAR file must be a regular file")
	}
	if info.Size() <= 0 || info.Size() > maxStaticCanaryWARBytes {
		return nil, fmt.Errorf("WAR file size must be between 1 byte and %d bytes", maxStaticCanaryWARBytes)
	}

	reader, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("open WAR as ZIP: %w", err)
	}
	defer reader.Close()
	if len(reader.File) != 1 {
		return nil, fmt.Errorf("static canary WAR must contain exactly one entry named index.html")
	}
	entry := reader.File[0]
	if entry.Name != "index.html" {
		return nil, fmt.Errorf("static canary WAR entry must be exactly index.html")
	}
	entryInfo := entry.FileInfo()
	if !entryInfo.Mode().IsRegular() || entryInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("static canary WAR entry must be a regular file")
	}
	if entry.UncompressedSize64 > 4096 || entry.CompressedSize64 > maxStaticCanaryWARBytes {
		return nil, fmt.Errorf("static canary index.html exceeds the allowed size")
	}
	stream, err := entry.Open()
	if err != nil {
		return nil, fmt.Errorf("open static canary index.html: %w", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(stream, 4097))
	closeErr := stream.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read static canary index.html: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close static canary index.html: %w", closeErr)
	}
	if len(body) > 4096 {
		return nil, fmt.Errorf("static canary index.html exceeds the allowed size")
	}
	token, err := parseStaticCanaryHTML(body)
	if err != nil {
		return nil, err
	}

	inputArchive, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read WAR file: %w", err)
	}
	inputSum := sha256.Sum256(inputArchive)
	canonicalArchive, err := buildCanonicalCanaryWAR(token)
	if err != nil {
		return nil, err
	}
	artifact := newCanaryArtifact(canonicalArchive, token, "operator-supplied canonical static canary: "+filepath.Clean(path))
	artifact.SourceSHA256 = hex.EncodeToString(inputSum[:])
	return artifact, nil
}

func newCanaryArtifact(archive []byte, token, source string) *CanaryArtifact {
	sum := sha256.Sum256(archive)
	marker := canaryMarkerPrefix + token
	return &CanaryArtifact{
		Bytes:       append([]byte(nil), archive...),
		SHA256:      hex.EncodeToString(sum[:]),
		Token:       token,
		Marker:      marker,
		ContextPath: "/jr-canary-" + token[:12],
		Source:      source,
	}
}

func buildCanonicalCanaryWAR(token string) ([]byte, error) {
	body := staticCanaryHTML(token)
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	header := &zip.FileHeader{Name: "index.html", Method: zip.Store}
	header.SetModTime(time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC))
	entry, err := writer.CreateHeader(header)
	if err != nil {
		return nil, fmt.Errorf("create static canary archive entry: %w", err)
	}
	if _, err := entry.Write(body); err != nil {
		return nil, fmt.Errorf("write static canary archive entry: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("finalize static canary archive: %w", err)
	}
	return archive.Bytes(), nil
}

func staticCanaryHTML(token string) []byte {
	return []byte("<!doctype html>\n" +
		"<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Jerry's Revenge deployment canary</title></head>\n" +
		"<body><pre>" + canaryMarkerPrefix + token + "</pre></body></html>\n")
}

func parseStaticCanaryHTML(body []byte) (string, error) {
	prefix := []byte("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Jerry's Revenge deployment canary</title></head>\n<body><pre>" + canaryMarkerPrefix)
	suffix := []byte("</pre></body></html>\n")
	if !bytes.HasPrefix(body, prefix) || !bytes.HasSuffix(body, suffix) {
		return "", fmt.Errorf("index.html does not match the canonical static canary profile")
	}
	tokenBytes := body[len(prefix) : len(body)-len(suffix)]
	token := string(tokenBytes)
	if !canaryTokenPattern.MatchString(token) {
		return "", fmt.Errorf("static canary token must match %s", canaryTokenPattern.String())
	}
	if !bytes.Equal(body, staticCanaryHTML(token)) {
		return "", fmt.Errorf("index.html does not match the canonical static canary profile")
	}
	return token, nil
}
