// Package report renders check results as a table, JSON, JSON Lines or CSV.
package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/quanticdata-io/proxy-checker/pkg/checker"
)

// Format is an output format.
type Format string

// Output formats.
const (
	Table Format = "table"
	JSON  Format = "json"
	JSONL Format = "jsonl"
	CSV   Format = "csv"
)

// ParseFormat validates a format name.
func ParseFormat(s string) (Format, error) {
	switch f := Format(strings.ToLower(s)); f {
	case Table, JSON, JSONL, CSV:
		return f, nil
	}
	return "", fmt.Errorf("unknown output format %q (table, json, jsonl, csv)", s)
}

// Write renders results in the given format. details keeps per-attempt data.
func Write(w io.Writer, f Format, results []checker.Result, details bool) error {
	if !details {
		trimmed := make([]checker.Result, len(results))
		for i, r := range results {
			r.Tries = nil
			trimmed[i] = r
		}
		results = trimmed
	}
	switch f {
	case JSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			Summary checker.Summary  `json:"summary"`
			Results []checker.Result `json:"results"`
		}{checker.Summarise(results), results})
	case JSONL:
		enc := json.NewEncoder(w)
		for _, r := range results {
			if err := enc.Encode(r); err != nil {
				return err
			}
		}
		return nil
	case CSV:
		return writeCSV(w, results)
	default:
		return writeTable(w, results)
	}
}

// CSVHeader is the column list of the CSV output.
var CSVHeader = []string{
	"proxy", "protocol", "pass", "success_rate", "successes", "attempts",
	"p50_ms", "p95_ms", "connect_avg_ms", "ttfb_avg_ms",
	"exit_ip", "unique_ips", "country_code", "country", "region", "city",
	"anonymity", "target_status", "failures", "error",
}

func f1(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) }

func writeCSV(w io.Writer, results []checker.Result) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(CSVHeader); err != nil {
		return err
	}
	for _, r := range results {
		var p50, p95, conn, ttfb string
		if r.Latency != nil {
			p50, p95, conn, ttfb = f1(r.Latency.P50), f1(r.Latency.P95), f1(r.Latency.ConnectAvg), f1(r.Latency.TTFBAvg)
		}
		var exit, cc, country, region, city string
		if len(r.ExitIPs) > 0 {
			exit = r.ExitIPs[0]
		}
		if r.Geo != nil {
			cc, country, region, city = r.Geo.CountryCode, r.Geo.Country, r.Geo.Region, r.Geo.City
		}
		target := ""
		if r.Target != nil && r.Target.Status != 0 {
			target = strconv.Itoa(r.Target.Status)
		}
		row := []string{
			r.Proxy, r.Protocol, strconv.FormatBool(r.Pass), strconv.FormatFloat(r.Rate, 'f', 2, 64),
			strconv.Itoa(r.Successes), strconv.Itoa(r.Attempts), p50, p95, conn, ttfb,
			exit, strconv.Itoa(r.UniqueIPs), cc, country, region, city,
			r.Anonymity, target, strings.Join(r.Failures, "; "), r.Error,
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func writeTable(w io.Writer, results []checker.Result) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PROXY\tRESULT\tOK\tP50\tP95\tEXIT IP\tIPS\tCOUNTRY\tANON\tNOTE")
	for _, r := range results {
		status := "PASS"
		if !r.Pass {
			status = "FAIL"
		}
		p50, p95 := "-", "-"
		if r.Latency != nil {
			p50, p95 = fmt.Sprintf("%.0fms", r.Latency.P50), fmt.Sprintf("%.0fms", r.Latency.P95)
		}
		exit := "-"
		if len(r.ExitIPs) > 0 {
			exit = r.ExitIPs[0]
		}
		country := "-"
		if r.Geo != nil && r.Geo.CountryCode != "" {
			country = r.Geo.CountryCode
			if r.Geo.City != "" {
				country += " " + r.Geo.City
			}
		}
		anon := r.Anonymity
		if anon == "" {
			anon = "-"
		}
		note := strings.Join(r.Failures, "; ")
		if len(note) > 70 {
			note = note[:67] + "..."
		}
		fmt.Fprintf(tw, "%s\t%s\t%d/%d\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n",
			r.Proxy, status, r.Successes, r.Attempts, p50, p95, exit, r.UniqueIPs, country, anon, note)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	s := checker.Summarise(results)
	line := fmt.Sprintf("\n%d checked, %d passed, %d failed (%.1f%% pass), %d unique exit IPs", s.Total, s.Passed, s.Failed, s.PassRate, s.UniqueIPs)
	if s.MedianP50 > 0 {
		line += fmt.Sprintf(", median p50 %.0fms", s.MedianP50)
	}
	if len(s.ByCountry) > 0 {
		keys := make([]string, 0, len(s.ByCountry))
		for k := range s.ByCountry {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s %d", k, s.ByCountry[k]))
		}
		line += ", countries: " + strings.Join(parts, ", ")
	}
	_, err := fmt.Fprintln(w, line)
	return err
}
