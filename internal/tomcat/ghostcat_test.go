package tomcat

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAssessGhostcatVersion(t *testing.T) {
	tests := []struct {
		version        string
		matched        bool
		authoritative  bool
		classification Classification
		firstFixed     string
	}{
		{"7.0.99", true, true, Potential, "7.0.100"},
		{"7.0.100", false, true, Unverified, "7.0.100"},
		{"8.5.50", true, true, Potential, "8.5.51"},
		{"8.5.51", false, true, Unverified, "8.5.51"},
		{"9.0.0.M1", true, true, Potential, "9.0.31"},
		{"9.0.30", true, true, Potential, "9.0.31"},
		{"9.0.31", false, true, Unverified, "9.0.31"},
		{"5.5.36", false, false, Unverified, ""},
		{"8.0.53", false, false, Unverified, ""},
		{"10.0.10", false, true, Unverified, ""},
		{"", false, false, Unverified, ""},
	}
	for _, test := range tests {
		t.Run(test.version, func(t *testing.T) {
			got := AssessGhostcatVersion(test.version)
			if got.VersionMatched != test.matched || got.Authoritative != test.authoritative || got.Classification != test.classification || got.FirstFixed != test.firstFixed {
				t.Fatalf("AssessGhostcatVersion(%q) = %+v", test.version, got)
			}
		})
	}
}

func TestNormalizeGhostcatFile(t *testing.T) {
	for input, want := range map[string]string{
		"WEB-INF/web.xml":   "WEB-INF/web.xml",
		"/WEB-INF/web.xml":  "WEB-INF/web.xml",
		"assets/config.yml": "assets/config.yml",
	} {
		got, err := NormalizeGhostcatFile(input)
		if err != nil {
			t.Fatalf("NormalizeGhostcatFile(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("NormalizeGhostcatFile(%q) = %q, want %q", input, got, want)
		}
	}
	for _, input := range []string{"", "../conf/server.xml", "WEB-INF//web.xml", "./WEB-INF/web.xml", "http://example.test/a", "WEB-INF/web.xml?x=1", "WEB-INF\\web.xml", "WEB-INF/%2e%2e/conf/server.xml", "WEB-INF;ignored/web.xml"} {
		if _, err := NormalizeGhostcatFile(input); err == nil {
			t.Fatalf("NormalizeGhostcatFile(%q) unexpectedly succeeded", input)
		}
	}
}

func TestReadGhostcatFileRejectsUnsafeEvidenceDirectoryBeforeConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	unsafeDir := filepath.Join(t.TempDir(), "unsafe")
	if err := os.Mkdir(unsafeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().(*net.TCPAddr)
	result := ReadGhostcatFile(context.Background(), GhostcatConfig{
		Host:       "127.0.0.1",
		Port:       address.Port,
		ServerName: "example.test",
		ServerPort: 8080,
		File:       "WEB-INF/web.xml",
		Timeout:    100 * time.Millisecond,
		OutputDir:  unsafeDir,
		EvidenceID: "test-run",
	})
	if result.Executed || result.RequestSent || result.RequestCount != 0 {
		t.Fatalf("unsafe evidence directory caused network activity: %+v", result)
	}
}

func TestReadGhostcatFileLoopback(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverErr <- acceptErr
			return
		}
		defer conn.Close()
		header := make([]byte, 4)
		if _, readErr := io.ReadFull(conn, header); readErr != nil {
			serverErr <- readErr
			return
		}
		if !bytes.Equal(header[:2], []byte{0x12, 0x34}) {
			serverErr <- fmt.Errorf("request magic = %x", header[:2])
			return
		}
		payload := make([]byte, int(binary.BigEndian.Uint16(header[2:4])))
		if _, readErr := io.ReadFull(conn, payload); readErr != nil {
			serverErr <- readErr
			return
		}
		for _, required := range []string{
			"javax.servlet.include.request_uri",
			"javax.servlet.include.path_info",
			"javax.servlet.include.servlet_path",
			"WEB-INF/web.xml",
		} {
			if !bytes.Contains(payload, []byte(required)) {
				serverErr <- fmt.Errorf("request omitted %q", required)
				return
			}
		}

		headers := []byte{ajpSendHeaders, 0x00, 0xc8}
		headers, _ = appendAJPString(headers, stringPointer("OK"))
		headers = append(headers, 0x00, 0x01, 0xa0, 0x01)
		headers, _ = appendAJPString(headers, stringPointer("application/xml"))
		body := []byte("<?xml version=\"1.0\"?><web-app><display-name>loopback</display-name></web-app>")
		chunk := []byte{ajpSendBodyChunk, byte(len(body) >> 8), byte(len(body))}
		chunk = append(chunk, body...)
		chunk = append(chunk, 0x00)
		for _, frame := range [][]byte{headers, chunk, []byte{ajpEndResponse, 0x01}} {
			if writeErr := writeTestAJPFrame(conn, frame); writeErr != nil {
				serverErr <- writeErr
				return
			}
		}
		serverErr <- nil
	}()

	address := listener.Addr().(*net.TCPAddr)
	outputDir := filepath.Join(t.TempDir(), "restricted", "ghostcat")
	result := ReadGhostcatFile(context.Background(), GhostcatConfig{
		Host:       "127.0.0.1",
		Port:       address.Port,
		ServerName: "example.test",
		ServerPort: 8080,
		File:       "WEB-INF/web.xml",
		Timeout:    2 * time.Second,
		OutputDir:  outputDir,
		EvidenceID: "test-run",
	})
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	if !result.Executed || result.RequestCount != 1 || !result.ProtocolConfirmed || !result.BodyAcquired || !result.FileReadConfirmed || result.Classification != Confirmed {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.ResponseMagic != "4142" || result.ResponseStatusCode != 200 || result.BodySHA256 == "" {
		t.Fatalf("unexpected response metadata: %+v", result)
	}
	content, err := os.ReadFile(result.EvidencePath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "<web-app>") || bytes.HasSuffix(content, []byte{0x00}) {
		t.Fatalf("unexpected restricted content: %q", content)
	}
	info, err := os.Stat(result.EvidencePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("evidence mode = %o, want 600", info.Mode().Perm())
	}
	dirInfo, err := os.Stat(outputDir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("output directory mode = %o, want 700", dirInfo.Mode().Perm())
	}
}

func TestNonDefaultGhostcatBodyRequiresOperatorConfirmation(t *testing.T) {
	body := []byte("database.url=jdbc:example")
	if confirmGhostcatFileRead("WEB-INF/classes/application.properties", 200, body, false) {
		t.Fatal("non-default file was automatically confirmed without a content marker")
	}
	if !plausibleGhostcatBody(200, body, false) {
		t.Fatal("plausible non-default body was not retained for operator review")
	}
}

func TestReadGhostcatResponseRejectsWrongDirectionMagic(t *testing.T) {
	frame := []byte{0x12, 0x34, 0x00, 0x02, ajpEndResponse, 0x01}
	result, body, err := readGhostcatResponse(bytes.NewReader(frame))
	if err == nil {
		t.Fatal("wrong-direction AJP magic unexpectedly succeeded")
	}
	if result.magic != "1234" || result.protocolConfirmed || len(body) != 0 {
		t.Fatalf("unexpected rejected response metadata: result=%+v body=%x", result, body)
	}
}

func stringPointer(value string) *string {
	return &value
}

func writeTestAJPFrame(writer io.Writer, payload []byte) error {
	header := []byte{0x41, 0x42, byte(len(payload) >> 8), byte(len(payload))}
	if err := writeAll(writer, header); err != nil {
		return err
	}
	return writeAll(writer, payload)
}
