package cli

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quanticdata-io/proxy-checker/internal/testutil"
)

type harness struct {
	echo, proxy *httptest.Server
	dead        string
}

func newHarness(t *testing.T, hp *testutil.HTTPProxy) harness {
	t.Helper()
	echo := httptest.NewServer(testutil.EchoHandler())
	t.Cleanup(echo.Close)
	ps := httptest.NewServer(hp)
	t.Cleanup(ps.Close)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	return harness{echo: echo, proxy: ps, dead: dead}
}

func (h harness) live() string { return strings.TrimPrefix(h.proxy.URL, "http://") }

func runCLI(t *testing.T, stdin string, env map[string]string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	e := Env{
		Stdin: strings.NewReader(stdin), StdinPiped: stdin != "", Stdout: &out, Stderr: &errb,
		Getenv: func(k string) string { return env[k] },
	}
	code := run(context.Background(), args, e)
	return code, out.String(), errb.String()
}

func TestVersion(t *testing.T) {
	code, out, _ := runCLI(t, "", nil, "version")
	if code != ExitOK || !strings.HasPrefix(out, "proxy-checker ") {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

func TestNoProxies(t *testing.T) {
	code, _, errOut := runCLI(t, "", nil)
	if code != ExitUsage || !strings.Contains(errOut, "no proxies to check") {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
}

func TestBadFlags(t *testing.T) {
	if code, _, _ := runCLI(t, "", nil, "--output", "xml", "h.example:1"); code != ExitUsage {
		t.Fatalf("code=%d", code)
	}
	if code, _, _ := runCLI(t, "", nil, "--protocol", "ftp", "h.example:1"); code != ExitUsage {
		t.Fatalf("code=%d", code)
	}
	if code, _, _ := runCLI(t, "", nil, "--no-such-flag"); code != ExitUsage {
		t.Fatalf("code=%d", code)
	}
}

func TestTableFromArgsWithTrailingFlags(t *testing.T) {
	h := newHarness(t, &testutil.HTTPProxy{Exit: testutil.ExitSticky, Country: "DE"})
	code, out, errOut := runCLI(t, "", nil, h.live(), "--echo-url", h.echo.URL+"/ip", "-n", "2")
	if code != ExitOK {
		t.Fatalf("code=%d err=%s", code, errOut)
	}
	for _, want := range []string{"PASS", "203.0.113.10", "DE Test City", "1 checked, 1 passed"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

func TestStdinJSONAndFailUnder(t *testing.T) {
	h := newHarness(t, &testutil.HTTPProxy{})
	stdin := "# list\n" + h.live() + "\n" + h.dead + "\nnot a proxy\n"
	code, out, errOut := runCLI(t, stdin, nil, "--echo-url", h.echo.URL+"/ip", "-n", "1", "--retries", "0", "--json", "--fail-under", "75")
	if code != ExitBelowGoal {
		t.Fatalf("code=%d err=%s", code, errOut)
	}
	if !strings.Contains(errOut, "skipping line 4") || !strings.Contains(errOut, "below --fail-under") {
		t.Fatalf("stderr = %s", errOut)
	}
	var doc struct {
		Summary struct {
			Total, Passed int
		} `json:"summary"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || doc.Summary.Total != 2 || doc.Summary.Passed != 1 {
		t.Fatalf("doc=%+v err=%v out=%s", doc, err, out)
	}
	// 50% passes a 50% goal.
	if code, _, _ := runCLI(t, stdin, nil, "--echo-url", h.echo.URL+"/ip", "-n", "1", "--retries", "0", "--json", "--fail-under", "50"); code != ExitOK {
		t.Fatalf("code=%d", code)
	}
}

func TestFileCSVAndSavePass(t *testing.T) {
	h := newHarness(t, &testutil.HTTPProxy{Username: "u", Password: "p"})
	dir := t.TempDir()
	list := filepath.Join(dir, "proxies.txt")
	if err := os.WriteFile(list, []byte(h.live()+":u:p\n"+h.dead+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(dir, "good.txt")
	code, out, errOut := runCLI(t, "", nil, "-f", list, "--echo-url", h.echo.URL+"/ip", "-n", "1", "--retries", "0", "--csv", "--save-pass", good)
	if code != ExitOK {
		t.Fatalf("code=%d err=%s", code, errOut)
	}
	rows, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil || len(rows) != 3 {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	if strings.Contains(out, ":p@") {
		t.Fatal("password leaked into the CSV")
	}
	saved, _ := os.ReadFile(good)
	if got := strings.TrimSpace(string(saved)); got != "http://u:p@"+h.live() {
		t.Fatalf("saved = %q", got)
	}
}

func TestQuanticDataPreset(t *testing.T) {
	h := newHarness(t, &testutil.HTTPProxy{Username: "user_1-country-us", Password: "pw", Country: "US"})
	var body map[string]any
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/public/proxies/generate" || r.Header.Get("Authorization") != "Bearer qd_test_k" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"type":"error","message":"Unauthorized"}`))
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		line := "http://user_1-country-us:pw@" + h.live()
		_, _ = w.Write([]byte(`{"type":"response","message":"success","payload":{"orderId":"ord_1","proxies":["` + line + `","` + line + `"]}}`))
	}))
	defer api.Close()
	env := map[string]string{"QUANTICDATA_API_KEY": "qd_test_k", "QUANTICDATA_API_BASE": api.URL + "/v1"}
	code, out, errOut := runCLI(t, "", env, "quanticdata", "--order-id", "ord_1", "--country", "us", "--quantity", "2", "--rotation", "sticky", "--session-time", "10", "--echo-url", h.echo.URL+"/ip", "-n", "1", "--jsonl")
	if code != ExitOK {
		t.Fatalf("code=%d err=%s", code, errOut)
	}
	if n := strings.Count(strings.TrimSpace(out), "\n") + 1; n != 2 {
		t.Fatalf("jsonl lines = %d\n%s", n, out)
	}
	if body["orderId"] != "ord_1" || body["country"] != "us" || body["rotation"] != "sticky" || body["format"] != "http://user:pass@host:port" {
		t.Fatalf("generate body = %v", body)
	}
	// --country us became an expect-country assertion: the proxy exits in US, so it passes.
	if !strings.Contains(out, `"pass":true`) {
		t.Fatalf("out = %s", out)
	}
}

func TestQuanticDataNeedsKey(t *testing.T) {
	code, _, errOut := runCLI(t, "", nil, "quanticdata", "--order-id", "x")
	if code != ExitUsage || !strings.Contains(errOut, "QUANTICDATA_API_KEY") {
		t.Fatalf("code=%d err=%s", code, errOut)
	}
}

func TestQuanticDataListPlans(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"type":"response","message":"ok","payload":{"proxies":[{"orderId":"ord_9","planType":"mobile","planName":"Mobile 5 GB","isActive":true}],"pagination":{"hasMore":false}}}`))
	}))
	defer api.Close()
	env := map[string]string{"QUANTICDATA_API_KEY": "qd_test_k", "QUANTICDATA_API_BASE": api.URL + "/v1"}
	code, out, _ := runCLI(t, "", env, "quanticdata", "--list-plans")
	if code != ExitOK || !strings.Contains(out, "ord_9") || !strings.Contains(out, "mobile") {
		t.Fatalf("code=%d out=%s", code, out)
	}
}
