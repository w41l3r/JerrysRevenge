package tomcat

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadWordlistFormatsAndDeduplicates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wordlist.txt")
	content := "# comment\nadmin:secret:with:colons\ntomcat password\nblank:\nadmin:secret:with:colons\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	credentials, err := LoadWordlist(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials) != 3 {
		t.Fatalf("got %d credentials, want 3", len(credentials))
	}
	if credentials[0].Password != "secret:with:colons" {
		t.Fatalf("colon password was not preserved")
	}
	if credentials[2].Password != "" {
		t.Fatalf("empty password was not preserved")
	}
}

func TestLoadCredentialFileRequiresExactlyOneColonPair(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential.txt")
	if err := os.WriteFile(path, []byte("# comment\noperator:value:with:colons\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	credential, err := LoadCredentialFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if credential.Username != "operator" || credential.Password != "value:with:colons" || credential.Ref != "CREDENTIAL-FILE-000001" {
		t.Fatalf("unexpected credential metadata: %+v", credential)
	}

	if err := os.WriteFile(path, []byte("one:first\ntwo:second\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredentialFile(path); err == nil {
		t.Fatal("multiple credentials were unexpectedly accepted")
	}
}
