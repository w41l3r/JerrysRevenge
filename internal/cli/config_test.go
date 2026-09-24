package cli

import (
	"bytes"
	"testing"
	"time"
)

func TestParseRequiresExactlyOneTargetSource(t *testing.T) {
	now := time.Date(2026, 9, 22, 1, 2, 3, 0, time.FixedZone("BRT", -3*60*60))
	for _, args := range [][]string{
		{},
		{"-u", "https://one.test", "-l", "targets.txt"},
	} {
		if _, err := Parse(args, &bytes.Buffer{}, now); err == nil {
			t.Fatalf("Parse(%v) unexpectedly succeeded", args)
		}
	}
}

func TestParseBruteAliasesAndDefaults(t *testing.T) {
	now := time.Date(2026, 9, 22, 1, 2, 3, 0, time.FixedZone("BRT", -3*60*60))
	cfg, err := Parse([]string{"--url", "https://example.test", "--brute", "--wordlist", "wordlist.txt", "--threads", "7", "--continue-on-success"}, &bytes.Buffer{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Brute || !cfg.ContinueOnSuccess || cfg.Threads != 7 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if cfg.Execute {
		t.Fatal("execution gate must default to false")
	}
	if cfg.Report == "" || cfg.CredentialOutput == "" {
		t.Fatal("evidence paths must have defaults")
	}
}

func TestParseBruteUsesBundledWordlistAndAcceptsCompany(t *testing.T) {
	now := time.Date(2026, 9, 22, 1, 2, 3, 0, time.FixedZone("BRT", -3*60*60))
	cfg, err := Parse([]string{"--url", "https://example.test", "--brute", "--company", "Acme Corp"}, &bytes.Buffer{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Brute || cfg.Wordlist != "" || cfg.Company != "Acme Corp" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	for _, args := range [][]string{
		{"--url", "https://example.test", "--company", "Acme"},
		{"--url", "https://example.test", "--company", "   ", "--brute"},
	} {
		if _, err := Parse(args, &bytes.Buffer{}, now); err == nil {
			t.Fatalf("Parse(%v) unexpectedly succeeded", args)
		}
	}
}

func TestParseGhostcatScopeAndDefaults(t *testing.T) {
	now := time.Date(2026, 9, 22, 1, 2, 3, 0, time.FixedZone("BRT", -3*60*60))
	cfg, err := Parse([]string{"--url", "https://example.test", "--ghostcat"}, &bytes.Buffer{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Ghostcat || cfg.GhostcatFile != "WEB-INF/web.xml" || cfg.AJPPort != 8009 {
		t.Fatalf("unexpected Ghostcat defaults: %+v", cfg)
	}

	invalid := [][]string{
		{"--url", "https://example.test", "--ajp-port", "8010"},
		{"--url", "https://example.test", "--ghostcat-file", "WEB-INF/web.xml"},
		{"--url", "https://example.test", "--ghostcat", "--ajp-port", "0"},
		{"--list", "targets.txt", "--ghostcat", "--ajp-host", "ajp.example.test"},
	}
	for _, args := range invalid {
		if _, err := Parse(args, &bytes.Buffer{}, now); err == nil {
			t.Fatalf("Parse(%v) unexpectedly succeeded", args)
		}
	}
}

func TestParseDeployCredentialRules(t *testing.T) {
	now := time.Date(2026, 9, 22, 1, 2, 3, 0, time.FixedZone("BRT", -3*60*60))
	valid := [][]string{
		{"-u", "https://example.test", "-e", "-U", "operator", "-P", "value"},
		{"-u", "https://example.test", "--exploit", "--creds-file", "credential.txt"},
		{"-u", "https://example.test", "--exploit", "--brute", "--wordlist", "wordlist.txt"},
	}
	for _, args := range valid {
		cfg, err := Parse(args, &bytes.Buffer{}, now)
		if err != nil {
			t.Fatalf("Parse(%v): %v", args, err)
		}
		if !cfg.DeployCheck {
			t.Fatalf("Parse(%v) did not enable deploy check", args)
		}
	}

	invalid := [][]string{
		{"-u", "https://example.test", "-e"},
		{"-u", "https://example.test", "-e", "-U", "operator"},
		{"-u", "https://example.test", "-e", "-P", "value"},
		{"-u", "https://example.test", "-e", "-U", "operator", "-P", "value", "--creds-file", "credential.txt"},
		{"-u", "https://example.test", "-e", "-b", "-w", "wordlist.txt", "-U", "operator", "-P", "value"},
		{"-u", "https://example.test", "--war-file", "canary.war"},
		{"-u", "https://example.test", "-U", "operator", "-P", "value"},
	}
	for _, args := range invalid {
		if _, err := Parse(args, &bytes.Buffer{}, now); err == nil {
			t.Fatalf("Parse(%v) unexpectedly succeeded", args)
		}
	}
}
