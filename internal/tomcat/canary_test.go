package tomcat

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultCanaryRoundTripsThroughStrictWARValidator(t *testing.T) {
	artifact, err := BuildDefaultCanary()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "canary.war")
	if err := os.WriteFile(path, artifact.Bytes, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadStaticCanaryWAR(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Marker != artifact.Marker || loaded.ContextPath != artifact.ContextPath || loaded.SHA256 != artifact.SHA256 {
		t.Fatalf("loaded artifact differs: got %+v want %+v", loaded, artifact)
	}
}

func TestStaticCanaryWARRejectsExecutableOrAdditionalEntries(t *testing.T) {
	tests := []struct {
		name    string
		entries map[string]string
	}{
		{
			name: "jsp",
			entries: map[string]string{
				"cmd.jsp": "<% out.print(1); %>",
			},
		},
		{
			name: "extra entry",
			entries: map[string]string{
				"index.html": staticCanaryHTMLForTest("123456789012"),
				"extra.txt":  "extra",
			},
		},
		{
			name: "noncanonical html",
			entries: map[string]string{
				"index.html": "<html>hello</html>",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "candidate.war")
			var archive bytes.Buffer
			writer := zip.NewWriter(&archive)
			for name, content := range test.entries {
				entry, err := writer.Create(name)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := entry.Write([]byte(content)); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, archive.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadStaticCanaryWAR(path); err == nil {
				t.Fatal("unsafe or noncanonical WAR was unexpectedly accepted")
			}
		})
	}
}

func TestStaticCanaryWARIsRepackedBeforeUpload(t *testing.T) {
	const token = "abcdefghijklmnopqrstuvwx"
	var source bytes.Buffer
	writer := zip.NewWriter(&source)
	entry, err := writer.Create("index.html")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write(staticCanaryHTML(token)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "compressed-source.war")
	if err := os.WriteFile(path, source.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	artifact, err := LoadStaticCanaryWAR(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(source.Bytes(), artifact.Bytes) {
		t.Fatal("source archive was not normalized before upload")
	}
	if artifact.SourceSHA256 == artifact.SHA256 {
		t.Fatal("source and normalized archive hashes unexpectedly match")
	}
	if artifact.Marker != canaryMarkerPrefix+token {
		t.Fatalf("marker = %q", artifact.Marker)
	}
}

func staticCanaryHTMLForTest(token string) string {
	return string(staticCanaryHTML(token))
}
