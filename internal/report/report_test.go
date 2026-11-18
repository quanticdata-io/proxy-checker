package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"github.com/quanticdata-io/proxy-checker/pkg/checker"
)

func sample() []checker.Result {
	return []checker.Result{
		{
			Proxy: "http://u:xxxxx@gw.example.net:8080", Protocol: "http", Pass: true, Attempts: 3, Successes: 3, Rate: 1,
			Latency: &checker.Latency{P50: 120, P95: 180}, ExitIPs: []string{"203.0.113.10"}, UniqueIPs: 1,
			Geo:   &checker.Echo{IP: "203.0.113.10", CountryCode: "US", Country: "United States", City: "New York"},
			Tries: []checker.Attempt{{OK: true, TotalMs: 120}},
		},
		{Proxy: "http://198.51.100.9:3128", Protocol: "http", Attempts: 3, Error: "timeout", Failures: []string{"unreachable: timeout"}},
	}
}

func TestParseFormat(t *testing.T) {
	for _, s := range []string{"table", "JSON", "jsonl", "csv"} {
		if _, err := ParseFormat(s); err != nil {
			t.Errorf("ParseFormat(%q): %v", s, err)
		}
	}
	if _, err := ParseFormat("xml"); err == nil {
		t.Error("xml should be rejected")
	}
}

func TestJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, JSON, sample(), false); err != nil {
		t.Fatal(err)
	}
	var out struct {
		Summary checker.Summary  `json:"summary"`
		Results []checker.Result `json:"results"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Summary.Passed != 1 || out.Summary.Failed != 1 || len(out.Results) != 2 || out.Results[0].Tries != nil {
		t.Fatalf("out = %+v", out)
	}
	buf.Reset()
	_ = Write(&buf, JSON, sample(), true)
	if !strings.Contains(buf.String(), `"tries"`) {
		t.Error("details must keep per-attempt data")
	}
}

func TestJSONL(t *testing.T) {
	var buf bytes.Buffer
	_ = Write(&buf, JSONL, sample(), false)
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %d", len(lines))
	}
	for _, l := range lines {
		var r checker.Result
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCSV(t *testing.T) {
	var buf bytes.Buffer
	_ = Write(&buf, CSV, sample(), false)
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || len(rows[0]) != len(CSVHeader) {
		t.Fatalf("rows = %v", rows)
	}
	if rows[1][2] != "true" || rows[1][10] != "203.0.113.10" || rows[1][12] != "US" || rows[2][19] != "timeout" {
		t.Fatalf("rows = %v", rows)
	}
}

func TestTable(t *testing.T) {
	var buf bytes.Buffer
	_ = Write(&buf, Table, sample(), false)
	out := buf.String()
	for _, want := range []string{"PROXY", "PASS", "FAIL", "203.0.113.10", "US New York", "2 checked, 1 passed, 1 failed (50.0% pass)"} {
		if !strings.Contains(out, want) {
			t.Errorf("table misses %q:\n%s", want, out)
		}
	}
}
