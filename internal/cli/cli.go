// Package cli implements the proxy-checker command line.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/quanticdata-io/proxy-checker/internal/quanticdata"
	"github.com/quanticdata-io/proxy-checker/internal/report"
	"github.com/quanticdata-io/proxy-checker/pkg/checker"
	"github.com/quanticdata-io/proxy-checker/pkg/proxy"
)

// Exit codes.
const (
	ExitOK        = 0
	ExitBelowGoal = 1 // --fail-under was not met
	ExitUsage     = 2 // bad flags or input
	ExitRuntime   = 3 // the run could not complete (API error, I/O error)
)

// Env is what the command reads and writes; tests substitute it.
type Env struct {
	Stdin      io.Reader
	StdinPiped bool
	Stdout     io.Writer
	Stderr     io.Writer
	Getenv     func(string) string
}

// OSEnv is the real process environment.
func OSEnv() Env {
	piped := false
	if st, err := os.Stdin.Stat(); err == nil {
		piped = st.Mode()&os.ModeCharDevice == 0
	}
	return Env{Stdin: os.Stdin, StdinPiped: piped, Stdout: os.Stdout, Stderr: os.Stderr, Getenv: os.Getenv}
}

const usage = `proxy-checker checks HTTP, HTTPS, SOCKS4 and SOCKS5 proxies: reachability,
latency, success rate, exit IP and country, anonymity, a target site, and IP
rotation or sticky sessions.

Usage:
  proxy-checker [flags] [proxy ...]            check proxies from args, -f FILE or stdin
  proxy-checker quanticdata [flags]            generate and check proxies of a QuanticData plan
  proxy-checker quanticdata --list-plans       list the proxy plans of your QuanticData account
  proxy-checker version

Proxy formats: host:port, user:pass@host:port, host:port:user:pass,
scheme://[user:pass@]host:port (http, https, socks4, socks4a, socks5, socks5h).

Examples:
  proxy-checker 203.0.113.7:3128 socks5://user:pass@198.51.100.4:1080
  proxy-checker -f proxies.txt --expect-country US --csv > report.csv
  cat proxies.txt | proxy-checker --target https://example.com --expect-text "Example Domain"
  proxy-checker -n 10 --expect-rotation gw.example.net:8080:user:pass
  QUANTICDATA_API_KEY=... proxy-checker quanticdata --order-id ORDER --country us --quantity 5

Flags:
`

type options struct {
	file          string
	protocol      string
	echoURL       string
	noEcho        bool
	attempts      int
	retries       int
	timeout       time.Duration
	concurrency   int
	expectCountry string
	expectRot     bool
	expectSticky  bool
	minSuccess    float64
	target        string
	expectStatus  int
	expectText    string
	headersURL    string
	realIP        string
	detectRealIP  bool
	output        string
	jsonOut       bool
	jsonlOut      bool
	csvOut        bool
	details       bool
	showCreds     bool
	failUnder     float64
	savePass      string
	insecure      bool
	userAgent     string

	// quanticdata subcommand
	orderID     string
	quantity    int
	country     string
	state       string
	city        string
	rotation    string
	sessionTime int
	gateway     string
	listPlans   bool
}

func newFlagSet(o *options, env Env, qd bool) *flag.FlagSet {
	fs := flag.NewFlagSet("proxy-checker", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	fs.Usage = func() {
		fmt.Fprint(env.Stderr, usage)
		fs.PrintDefaults()
	}
	def := checker.DefaultOptions()
	str := func(p *string, names []string, value, help string) {
		for _, n := range names {
			fs.StringVar(p, n, value, help)
		}
	}
	intv := func(p *int, names []string, value int, help string) {
		for _, n := range names {
			fs.IntVar(p, n, value, help)
		}
	}
	boolv := func(p *bool, names []string, help string) {
		for _, n := range names {
			fs.BoolVar(p, n, false, help)
		}
	}
	str(&o.file, []string{"f", "file"}, "", "read proxies from `FILE` (one per line, '#' comments; '-' for stdin)")
	str(&o.protocol, []string{"protocol"}, "http", "protocol for lines without a scheme: http, https, socks4, socks5")
	str(&o.echoURL, []string{"echo-url"}, def.EchoURL, "IP echo `URL` (JSON or plain text) used for exit IP and country")
	boolv(&o.noEcho, []string{"no-echo"}, "skip the IP echo (needs --target)")
	intv(&o.attempts, []string{"n", "attempts"}, def.Attempts, "requests per proxy (use 5-20 for rotation checks)")
	intv(&o.retries, []string{"retries"}, def.Retries, "retries of a request after a connection error")
	fs.DurationVar(&o.timeout, "timeout", def.Timeout, "timeout of one request")
	intv(&o.concurrency, []string{"c", "concurrency"}, def.Concurrency, "proxies checked in parallel")
	str(&o.expectCountry, []string{"expect-country"}, "", "fail proxies whose exit country is not `CC` (ISO code)")
	boolv(&o.expectRot, []string{"expect-rotation"}, "fail proxies that keep one exit IP across attempts")
	boolv(&o.expectSticky, []string{"expect-sticky"}, "fail proxies whose exit IP changes across attempts")
	fs.Float64Var(&o.minSuccess, "min-success", 0, "fail proxies whose request success rate is below `PERCENT`")
	str(&o.target, []string{"target"}, "", "also fetch `URL` through each proxy")
	intv(&o.expectStatus, []string{"expect-status"}, 0, "status the target must answer (default: any 2xx/3xx)")
	str(&o.expectText, []string{"expect-text"}, "", "text the target body must contain")
	str(&o.headersURL, []string{"headers-url"}, "", "plain-http header echo `URL` ({\"headers\":{...}}) for the anonymity check")
	str(&o.realIP, []string{"real-ip"}, "", "your public IP, to detect transparent proxies")
	boolv(&o.detectRealIP, []string{"detect-real-ip"}, "find your public IP with one direct request to the echo URL")
	str(&o.output, []string{"o", "output"}, "table", "output format: table, json, jsonl, csv")
	boolv(&o.jsonOut, []string{"json"}, "shorthand for --output json")
	boolv(&o.jsonlOut, []string{"jsonl"}, "shorthand for --output jsonl")
	boolv(&o.csvOut, []string{"csv"}, "shorthand for --output csv")
	boolv(&o.details, []string{"details"}, "include every attempt in JSON output")
	boolv(&o.showCreds, []string{"show-credentials"}, "print passwords instead of masking them")
	fs.Float64Var(&o.failUnder, "fail-under", 0, "exit with code 1 when fewer than `PERCENT` of the proxies pass")
	str(&o.savePass, []string{"save-pass"}, "", "write the proxies that passed to `FILE`, one URL per line")
	boolv(&o.insecure, []string{"insecure"}, "do not verify TLS certificates (targets and HTTPS proxies)")
	str(&o.userAgent, []string{"user-agent"}, "", "User-Agent header of the test requests")
	if qd {
		str(&o.orderID, []string{"order-id"}, "", "QuanticData order `ID` of the proxy plan (see --list-plans)")
		intv(&o.quantity, []string{"quantity"}, 10, "number of proxy strings to generate (1-10000)")
		str(&o.country, []string{"country"}, "", "country targeting passed to the generator (also checked as --expect-country when it is a 2-letter code)")
		str(&o.state, []string{"state"}, "", "state or region targeting")
		str(&o.city, []string{"city"}, "", "city targeting")
		str(&o.rotation, []string{"rotation"}, "", "rotating, sticky or static")
		intv(&o.sessionTime, []string{"session-time"}, 0, "sticky session length in minutes (1-1440)")
		str(&o.gateway, []string{"gateway"}, "", "entry gateway where the plan supports it: ww, us, eu, as")
		boolv(&o.listPlans, []string{"list-plans"}, "list the active proxy plans of the account and exit")
	}
	return fs
}

// parseInterleaved accepts flags before and after positional arguments.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		if rest[0] == "--" {
			return append(pos, rest[1:]...), nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

// Run executes the command and returns the exit code.
func Run(args []string, env Env) int {
	if env.Getenv == nil {
		env.Getenv = func(string) string { return "" }
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return run(ctx, args, env)
}

func run(ctx context.Context, args []string, env Env) int {
	qd := false
	if len(args) > 0 {
		switch args[0] {
		case "version", "--version", "-version":
			fmt.Fprintf(env.Stdout, "proxy-checker %s\n", checker.Version)
			return ExitOK
		case "quanticdata":
			qd = true
			args = args[1:]
		case "check":
			args = args[1:]
		}
	}
	var o options
	fs := newFlagSet(&o, env, qd)
	positional, err := parseInterleaved(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		return ExitOK
	}
	if err != nil {
		return ExitUsage
	}
	fail := func(code int, format string, a ...any) int {
		fmt.Fprintf(env.Stderr, "proxy-checker: "+format+"\n", a...)
		return code
	}

	defProto, err := proxy.ParseProtocol(o.protocol)
	if err != nil {
		return fail(ExitUsage, "%v", err)
	}
	format := o.output
	switch {
	case o.jsonOut:
		format = "json"
	case o.jsonlOut:
		format = "jsonl"
	case o.csvOut:
		format = "csv"
	}
	outFmt, err := report.ParseFormat(format)
	if err != nil {
		return fail(ExitUsage, "%v", err)
	}

	var proxies []proxy.Proxy
	if qd {
		client, err := quanticdata.NewFromEnvFunc(env.Getenv)
		if err != nil {
			return fail(ExitUsage, "%v", err)
		}
		client.UserAgent = "proxy-checker/" + checker.Version
		if o.listPlans {
			return listPlans(ctx, client, env)
		}
		if defProto != proxy.HTTP && defProto != proxy.SOCKS5 {
			return fail(ExitUsage, "the QuanticData generator supports --protocol http or socks5")
		}
		lines, err := client.Generate(ctx, quanticdata.GenerateRequest{
			OrderID: o.orderID, Protocol: string(defProto), Quantity: o.quantity, Country: o.country,
			State: o.state, City: o.city, Rotation: o.rotation, SessionTime: o.sessionTime, Gateway: o.gateway,
		})
		if err != nil {
			if o.orderID == "" {
				return fail(ExitUsage, "%v", err)
			}
			return fail(ExitRuntime, "%v", err)
		}
		for _, l := range lines {
			p, err := proxy.Parse(l, defProto)
			if err != nil {
				return fail(ExitRuntime, "unexpected proxy string from the API: %v", err)
			}
			proxies = append(proxies, p)
		}
		if o.expectCountry == "" && len(o.country) == 2 {
			o.expectCountry = o.country
		}
	} else {
		proxies, err = collect(o, positional, defProto, env)
		if err != nil {
			return fail(ExitUsage, "%v", err)
		}
	}
	if len(proxies) == 0 {
		fs.Usage()
		return fail(ExitUsage, "no proxies to check: pass them as arguments, with -f FILE or on stdin")
	}

	copts := checker.DefaultOptions()
	copts.EchoURL = o.echoURL
	if o.noEcho {
		copts.EchoURL = ""
	}
	copts.Attempts, copts.Retries, copts.Timeout, copts.Concurrency = o.attempts, o.retries, o.timeout, o.concurrency
	copts.ExpectCountry, copts.ExpectRotation, copts.ExpectSticky = o.expectCountry, o.expectRot, o.expectSticky
	copts.MinSuccessRate = o.minSuccess / 100
	copts.TargetURL, copts.ExpectStatus, copts.ExpectText = o.target, o.expectStatus, o.expectText
	copts.HeadersURL, copts.RealIP, copts.Insecure = o.headersURL, o.realIP, o.insecure
	if o.userAgent != "" {
		copts.UserAgent = o.userAgent
	}
	if o.detectRealIP && copts.RealIP == "" {
		ip, err := detectRealIP(ctx, copts)
		if err != nil {
			return fail(ExitRuntime, "cannot detect your public IP: %v", err)
		}
		copts.RealIP = ip
	}
	c, err := checker.New(copts)
	if err != nil {
		return fail(ExitUsage, "%v", err)
	}
	c.ShowCredentials = o.showCreds

	results := c.Run(ctx, proxies, nil)
	if err := report.Write(env.Stdout, outFmt, results, o.details); err != nil {
		return fail(ExitRuntime, "writing the report: %v", err)
	}
	if o.savePass != "" {
		if err := savePassing(o.savePass, proxies, results); err != nil {
			return fail(ExitRuntime, "%v", err)
		}
	}
	if ctx.Err() != nil {
		return fail(ExitRuntime, "interrupted")
	}
	if o.failUnder > 0 {
		s := checker.Summarise(results)
		if s.PassRate < o.failUnder {
			return fail(ExitBelowGoal, "%.1f%% of the proxies passed, below --fail-under %.1f%%", s.PassRate, o.failUnder)
		}
	}
	return ExitOK
}

func collect(o options, positional []string, def proxy.Protocol, env Env) ([]proxy.Proxy, error) {
	var out []proxy.Proxy
	for _, a := range positional {
		p, err := proxy.Parse(a, def)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	var r io.Reader
	switch {
	case o.file == "-":
		r = env.Stdin
	case o.file != "":
		f, err := os.Open(o.file)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	case len(positional) == 0 && env.StdinPiped:
		r = env.Stdin
	}
	if r != nil {
		list, bad, err := proxy.ReadList(r, def)
		if err != nil {
			return nil, err
		}
		for _, b := range bad {
			fmt.Fprintf(env.Stderr, "proxy-checker: skipping %v\n", b)
		}
		out = append(out, list...)
	}
	return out, nil
}

func detectRealIP(ctx context.Context, o checker.Options) (string, error) {
	if o.EchoURL == "" {
		return "", errors.New("needs an echo URL")
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.EchoURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", o.UserAgent)
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	e, ok := checker.ParseEcho(body)
	if !ok {
		return "", errors.New("the echo answer has no IP")
	}
	return e.IP, nil
}

func savePassing(path string, proxies []proxy.Proxy, results []checker.Result) error {
	var b strings.Builder
	for i, r := range results {
		if r.Pass {
			b.WriteString(proxies[i].String())
			b.WriteByte('\n')
		}
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

func listPlans(ctx context.Context, c *quanticdata.Client, env Env) int {
	plans, err := c.ListPlans(ctx)
	if err != nil {
		fmt.Fprintf(env.Stderr, "proxy-checker: %v\n", err)
		return ExitRuntime
	}
	if len(plans) == 0 {
		fmt.Fprintln(env.Stdout, "No active proxy plans on this account.")
		return ExitOK
	}
	fmt.Fprintf(env.Stdout, "%-28s %-20s %s\n", "ORDER ID", "PLAN TYPE", "PLAN")
	for _, p := range plans {
		fmt.Fprintf(env.Stdout, "%-28s %-20s %s\n", p.OrderID, p.PlanType, p.PlanName)
	}
	return ExitOK
}
