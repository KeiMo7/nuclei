//go:build integration
// +build integration

package integration_test

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
)

// The isolation cases run the real binary against a local server with a fixture
// of normal units plus a hanging network unit. The crash and leak fault classes
// are covered exhaustively by pkg/core's fixture tests, where a stub executer
// can panic or leak without needing a signed template; here the process-level
// contract is what is asserted: the rest of the scan runs, the isolation list
// and summary are written, isolated results stay out of the findings, the exit
// status is partial, and two identical runs agree.

func isolationServer(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			_, _ = w.Write([]byte("fixture-ok"))
		case "/ok2":
			_, _ = w.Write([]byte("fixture-ok2"))
		default:
			_, _ = w.Write([]byte("fixture-other"))
		}
	}))
	t.Cleanup(server.Close)
	return server.URL
}

// hangingTCPServer accepts connections and never answers, so a network
// template's read blocks until its unit deadline ends it.
func hangingTCPServer(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// held open until the test ends
			go func() {
				<-ctx.Done()
				_ = conn.Close()
			}()
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		<-done
	})
	return listener.Addr().String()
}

func readFixture(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(suite.fixturesDir, path))
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	return string(data)
}

func writeIsolationFixtures(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	fixtures := map[string]string{
		"ok.yaml":  readFixture(t, "isolation/ok.yaml"),
		"ok2.yaml": readFixture(t, "isolation/ok2.yaml"),
		"hang.yaml": `id: isolation-hang

info:
  name: Isolation fixture - hanging unit
  author: nuclei
  severity: info

tcp:
  - inputs:
      - data: "PING\r\n"
    host:
      - "{{Hostname}}"
    read-size: 16
    matchers:
      - type: word
        words: ["PONG"]
`,
	}
	for name, content := range fixtures {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write fixture %s: %v", name, err)
		}
	}
	return dir
}

func TestIsolationFixtureRunsTheRest(t *testing.T) {
	target := isolationServer(t)
	dir := writeIsolationFixtures(t)
	output := filepath.Join(t.TempDir(), "out.jsonl")

	result, err := testutils.RunNucleiWithStatus(suite.debug,
		"-t", dir, "-u", target,
		"-jsonl", "-o", output,
		"-duc",
	)
	if err != nil {
		t.Fatalf("isolation scan failed: %v", err)
	}
	findings, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read findings: %v", err)
	}
	if !bytes.Contains(findings, []byte("isolation-ok")) {
		t.Fatalf("a normal unit did not run: %s", findings)
	}
	if result.ExitCode != 0 {
		t.Fatalf("a scan that isolated nothing exited %d, want 0", result.ExitCode)
	}
	if _, err := os.Stat(output + ".isolation.txt"); !os.IsNotExist(err) {
		t.Fatalf("a scan that isolated nothing wrote an isolation list")
	}
}

func TestIsolationHangIsContainedAndListWritten(t *testing.T) {
	target := isolationServer(t)
	hanging := hangingTCPServer(t)
	dir := writeIsolationFixtures(t)
	output := filepath.Join(t.TempDir(), "out.jsonl")

	result, err := testutils.RunNucleiWithStatus(suite.debug,
		"-t", dir, "-u", target, "-u", hanging,
		"-jsonl", "-o", output,
		"-isolation-timeout", "2s",
		"-timeout", "1",
		"-duc",
	)
	if err != nil {
		t.Fatalf("isolation scan failed: %v", err)
	}
	if result.ExitCode != 2 {
		t.Fatalf("a scan that isolated a unit exited %d, want 2 (partial)", result.ExitCode)
	}

	findings, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read findings: %v", err)
	}
	for _, id := range []string{"isolation-ok", "isolation-ok-two"} {
		if !bytes.Contains(findings, []byte(id)) {
			t.Fatalf("normal unit %s is missing from the findings: %s", id, findings)
		}
	}
	if bytes.Contains(findings, []byte("isolation-hang")) {
		t.Fatalf("the isolated unit is in the findings list: %s", findings)
	}

	list, err := os.ReadFile(output + ".isolation.txt")
	if err != nil {
		t.Fatalf("the readable list was not written: %v", err)
	}
	text := string(list)
	for _, want := range []string{"isolation-hang", "reason=timeout", "template=isolation-hang"} {
		if !strings.Contains(text, want) {
			t.Fatalf("the isolation list does not mention %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "isolation-ok") {
		t.Fatalf("a normal unit is in the isolation list:\n%s", text)
	}

	summary, err := os.ReadFile(output + ".isolation.json")
	if err != nil {
		t.Fatalf("the machine-readable summary was not written: %v", err)
	}
	for _, want := range []string{`"isolated"`, `"decisions"`, `"isolation-hang"`} {
		if !bytes.Contains(summary, []byte(want)) {
			t.Fatalf("the summary does not contain %s:\n%s", want, summary)
		}
	}
}

// TestIsolationTwoRunsAgree checks the same job produces the same isolation
// list twice, so a delivery can be compared across runs.
func TestIsolationTwoRunsAgree(t *testing.T) {
	target := isolationServer(t)
	run := func(hanging string) []byte {
		dir := writeIsolationFixtures(t)
		output := filepath.Join(t.TempDir(), "out.jsonl")
		if _, err := testutils.RunNucleiWithStatus(suite.debug,
			"-t", dir, "-u", target, "-u", hanging,
			"-jsonl", "-o", output,
			"-isolation-timeout", "2s",
			"-timeout", "1",
			"-duc",
		); err != nil {
			t.Fatalf("isolation scan failed: %v", err)
		}
		list, err := os.ReadFile(output + ".isolation.txt")
		if err != nil {
			t.Fatalf("read list: %v", err)
		}
		return list
	}
	// both runs hang on the same kind of server; the port differs and is
	// stripped before the comparison
	first := run(hangingTCPServer(t))
	second := run(hangingTCPServer(t))

	stripTarget := func(list []byte) string {
		var kept []string
		for _, line := range strings.Split(string(list), "\n") {
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			kept = append(kept, line[:strings.Index(line, "\ttarget=")])
		}
		return strings.Join(kept, "\n")
	}
	if first, second := stripTarget(first), stripTarget(second); first != second {
		t.Fatalf("two identical runs produced different isolation lists:\n%s\n---\n%s\n%s", first, second, first)
	}
}
