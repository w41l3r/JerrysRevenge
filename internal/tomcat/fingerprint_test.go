package tomcat

import (
	"strings"
	"testing"
)

func TestAnalyzeFingerprintPrefersMostSpecificCompatibleVersion(t *testing.T) {
	result := AnalyzeFingerprint([]Probe{{
		URL:              "http://example.test/docs/",
		Signals:          []string{"title identifica Apache Tomcat"},
		DetectedVersions: []string{"10.0", "10.0.10"},
		body:             []byte(`<title>Apache Tomcat 10 (10.0.10)</title>`),
	}})
	if result.Version != "10.0.10" {
		t.Fatalf("version = %q, want 10.0.10", result.Version)
	}
	if len(result.Versions) != 1 {
		t.Fatalf("versions = %v, want one specific version", result.Versions)
	}
	if !strings.Contains(strings.Join(result.Evidence, " | "), "10.0") {
		t.Fatal("suppressed version was not preserved as evidence")
	}
}

func TestAnalyzeFingerprintPreservesGenuineVersionConflict(t *testing.T) {
	result := AnalyzeFingerprint([]Probe{{
		URL:              "http://example.test/docs/",
		Signals:          []string{"title identifica Apache Tomcat"},
		DetectedVersions: []string{"9.0.80", "9.0.82"},
		body:             []byte(`<title>Apache Tomcat</title>`),
	}})
	if result.Version != "9.0.80, 9.0.82" {
		t.Fatalf("version = %q, want conflict preserved", result.Version)
	}
}
