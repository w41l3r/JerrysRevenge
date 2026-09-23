package tomcat

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"strings"
	"testing"
)

func TestExtractCSRFTokenFromManagerHTML(t *testing.T) {
	const token = "test-csrf-nonce-for-unit-tests-12345"
	body := []byte(`<form action="/manager/html/upload?path=test&amp;org.apache.catalina.filters.CSRF_NONCE=` + token + `"></form>`)
	got, ok := extractCSRFToken(body)
	if !ok || got != token {
		t.Fatalf("token = %q, found=%t", got, ok)
	}
	if _, ok := extractCSRFToken([]byte(`org.apache.catalina.filters.CSRF_NONCE=short`)); ok {
		t.Fatal("short CSRF value was unexpectedly accepted")
	}
}

func TestBuildManagerHTMLUploadContainsOnlyValidatedArtifact(t *testing.T) {
	artifact, err := BuildDefaultCanary()
	if err != nil {
		t.Fatal(err)
	}
	body, contentType, filename, err := buildManagerHTMLUpload(artifact)
	if err != nil {
		t.Fatal(err)
	}
	mediaType, parameters, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "multipart/form-data" || parameters["boundary"] == "" {
		t.Fatalf("unexpected content type %q: %v", contentType, err)
	}
	reader := multipart.NewReader(bytes.NewReader(body), parameters["boundary"])
	part, err := reader.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if part.FormName() != "deployWar" || part.FileName() != filename || filename != strings.TrimPrefix(artifact.ContextPath, "/")+".war" {
		t.Fatalf("unexpected upload metadata: field=%q filename=%q", part.FormName(), part.FileName())
	}
	uploaded, err := io.ReadAll(part)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(uploaded, artifact.Bytes) {
		t.Fatal("multipart body changed the validated static canary")
	}
	if _, err := reader.NextPart(); err != io.EOF {
		t.Fatalf("unexpected additional multipart entry: %v", err)
	}
}
