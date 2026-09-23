package tomcat

import (
	"strings"
	"testing"
)

func TestBuildEndpointPreservesSemicolonAndDotSegment(t *testing.T) {
	target, err := ParseTarget("https://example.test/base/")
	if err != nil {
		t.Fatal(err)
	}
	got, err := BuildEndpoint(target, "/jr/..;/manager/html")
	if err != nil {
		t.Fatal(err)
	}
	want := "https://example.test/base/jr/..;/manager/html"
	if got != want {
		t.Fatalf("BuildEndpoint() = %q, want %q", got, want)
	}
}

func TestParseTargetRejectsAmbiguousOrSecretBearingURL(t *testing.T) {
	cases := []string{
		"example.test",
		"ftp://example.test/",
		"https://user:secret@example.test/",
		"https://example.test/?token=secret",
		"https://example.test/#fragment",
		"https://example.test/;jsessionid=secret/",
	}
	for _, testCase := range cases {
		t.Run(strings.ReplaceAll(testCase, "/", "_"), func(t *testing.T) {
			if _, err := ParseTarget(testCase); err == nil {
				t.Fatalf("ParseTarget(%q) unexpectedly succeeded", testCase)
			}
		})
	}
}
