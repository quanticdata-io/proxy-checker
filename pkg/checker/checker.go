// Package checker tests proxies: reachability, latency, success rate, exit IP,
// geolocation, anonymity, a target URL, and IP rotation or stickiness.
package checker

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/quanticdata-io/proxy-checker/pkg/proxy"
)

// DefaultEchoURL is QuanticData's free IP echo: no API key, never cached. It
// answers with the exit IP and where Cloudflare places it (country, region, city).
const DefaultEchoURL = "https://api.quanticdata.io/v1/public/ip-echo"

// Options configures a check run. The zero value is not usable: start from DefaultOptions.
type Options struct {
	// EchoURL answers with the exit IP (and optionally geo) as JSON or plain text.
	// Empty disables IP and geo checks; then TargetURL is used for the attempts.
	EchoURL string
	// Attempts per proxy. Use 5-20 for rotation and stickiness checks.
	Attempts int
	// Retries of one attempt after a transport error (not after an HTTP answer).
	Retries int
	// Timeout of one request, end to end.
	Timeout time.Duration
	// Concurrency is the number of proxies checked in parallel.
	Concurrency int
	// UserAgent sent with every request.
	UserAgent string
	// Insecure skips TLS verification of targets and HTTPS proxies.
	Insecure bool

	// ExpectCountry fails a proxy whose exit country (ISO code) differs. Empty: no check.
	ExpectCountry string
	// ExpectRotation fails a proxy that kept one exit IP over all successful attempts.
	ExpectRotation bool
	// ExpectSticky fails a proxy whose exit IP changed between attempts.
	ExpectSticky bool
	// MinSuccessRate fails a proxy whose attempt success rate (0..1) is lower.
	MinSuccessRate float64

	// TargetURL is fetched once per proxy (after the echo attempts) to test a real site.
	TargetURL string
	// ExpectStatus is the status TargetURL must answer; 0 accepts 200-399.
	ExpectStatus int
	// ExpectText must appear in the TargetURL body. Empty: no check.
	ExpectText string

	// HeadersURL is a header-echo endpoint (httpbin-style {"headers":{...}}), fetched
	// once per proxy to classify anonymity. It must be plain http:// to be meaningful:
	// through an HTTPS tunnel a proxy cannot add headers. Empty disables the check.
	HeadersURL string
	// RealIP is your own public IP, used to detect transparent proxies.
	RealIP string
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() Options {
	return Options{
		EchoURL:     DefaultEchoURL,
		Attempts:    3,
		Retries:     1,
		Timeout:     15 * time.Second,
		Concurrency: 20,
		UserAgent:   "proxy-checker/" + Version,
	}
}

// Version of the checker, set at build time by the release pipeline.
var Version = "0.1.0"

// Latency summarises the successful attempts, in milliseconds.
type Latency struct {
	Min        float64 `json:"min_ms"`
	P50        float64 `json:"p50_ms"`
	P95        float64 `json:"p95_ms"`
	Max        float64 `json:"max_ms"`
	ConnectAvg float64 `json:"connect_avg_ms"`
	TTFBAvg    float64 `json:"ttfb_avg_ms"`
}

// Attempt is one request through the proxy.
type Attempt struct {
	OK        bool    `json:"ok"`
	Status    int     `json:"status,omitempty"`
	ExitIP    string  `json:"exit_ip,omitempty"`
	ConnectMs float64 `json:"connect_ms,omitempty"`
	TTFBMs    float64 `json:"ttfb_ms,omitempty"`
	TotalMs   float64 `json:"total_ms"`
	Error     string  `json:"error,omitempty"`
}

// TargetResult is the outcome of the TargetURL request.
type TargetResult struct {
	URL       string  `json:"url"`
	OK        bool    `json:"ok"`
	Status    int     `json:"status,omitempty"`
	TextFound *bool   `json:"text_found,omitempty"`
	TotalMs   float64 `json:"total_ms"`
	Bytes     int     `json:"bytes"`
	Error     string  `json:"error,omitempty"`
}

// Result is the outcome for one proxy.
type Result struct {
	Proxy     string        `json:"proxy"`
	Protocol  string        `json:"protocol"`
	Pass      bool          `json:"pass"`
	Failures  []string      `json:"failures,omitempty"`
	Attempts  int           `json:"attempts"`
	Successes int           `json:"successes"`
	Rate      float64       `json:"success_rate"`
	Latency   *Latency      `json:"latency,omitempty"`
	ExitIPs   []string      `json:"exit_ips,omitempty"`
	UniqueIPs int           `json:"unique_ips"`
	Geo       *Echo         `json:"geo,omitempty"`
	Anonymity string        `json:"anonymity,omitempty"`
	Leaked    []string      `json:"leaked_headers,omitempty"`
	Target    *TargetResult `json:"target,omitempty"`
	Error     string        `json:"error,omitempty"`
	Tries     []Attempt     `json:"tries,omitempty"`
}

// Checker runs checks with fixed options.
type Checker struct {
	opts Options
	// ShowCredentials keeps passwords in Result.Proxy; by default they are masked.
	ShowCredentials bool
}

// New returns a Checker. It validates and normalises the options.
func New(opts Options) (*Checker, error) {
	if opts.Attempts < 1 {
		opts.Attempts = 1
	}
	if opts.Concurrency < 1 {
		opts.Concurrency = 1
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 15 * time.Second
	}
	if opts.Retries < 0 {
		opts.Retries = 0
	}
	if opts.EchoURL == "" && opts.TargetURL == "" {
		return nil, errors.New("nothing to test: set an echo URL or a target URL")
	}
	for _, u := range []string{opts.EchoURL, opts.TargetURL, opts.HeadersURL} {
		if u == "" {
			continue
		}
		pu, err := url.Parse(u)
		if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") || pu.Host == "" {
			return nil, fmt.Errorf("invalid URL %q (http or https expected)", u)
		}
	}
	if opts.ExpectRotation && opts.ExpectSticky {
		return nil, errors.New("expect rotation and expect sticky are mutually exclusive")
	}
	if (opts.ExpectRotation || opts.ExpectSticky) && opts.Attempts < 2 {
		return nil, errors.New("rotation and stickiness checks need at least 2 attempts")
	}
	if (opts.ExpectRotation || opts.ExpectSticky || opts.ExpectCountry != "") && opts.EchoURL == "" {
		return nil, errors.New("rotation, stickiness and country checks need an echo URL")
	}
	opts.ExpectCountry = strings.ToUpper(strings.TrimSpace(opts.ExpectCountry))
	if opts.UserAgent == "" {
		opts.UserAgent = "proxy-checker/" + Version
	}
	return &Checker{opts: opts}, nil
}

// Options returns the effective options.
func (c *Checker) Options() Options { return c.opts }

// Run checks every proxy with bounded concurrency and returns the results in input order.
// onResult, when not nil, is called as each proxy finishes (from several goroutines, serialised).
func (c *Checker) Run(ctx context.Context, proxies []proxy.Proxy, onResult func(i int, r Result)) []Result {
	results := make([]Result, len(proxies))
	jobs := make(chan int)
	var wg sync.WaitGroup
	var mu sync.Mutex
	workers := c.opts.Concurrency
	if workers > len(proxies) {
		workers = len(proxies)
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				r := c.Check(ctx, proxies[i])
				results[i] = r
				if onResult != nil {
					mu.Lock()
					onResult(i, r)
					mu.Unlock()
				}
			}
		}()
	}
	for i := range proxies {
		select {
		case jobs <- i:
		case <-ctx.Done():
			results[i] = Result{Proxy: c.display(proxies[i]), Protocol: string(proxies[i].Protocol), Error: ctx.Err().Error()}
		}
	}
	close(jobs)
	wg.Wait()
	return results
}

func (c *Checker) display(p proxy.Proxy) string {
	if c.ShowCredentials {
		return p.String()
	}
	return p.Redacted()
}

// Check runs every configured check against one proxy.
func (c *Checker) Check(ctx context.Context, p proxy.Proxy) Result {
	res := Result{Proxy: c.display(p), Protocol: string(p.Protocol), Attempts: c.opts.Attempts}
	client := c.client(p)
	defer client.CloseIdleConnections()

	probe := c.opts.EchoURL
	if probe == "" {
		probe = c.opts.TargetURL
	}
	seen := map[string]bool{}
	var lastErr string
	for i := 0; i < c.opts.Attempts; i++ {
		if ctx.Err() != nil {
			lastErr = ctx.Err().Error()
			break
		}
		a, body := c.attempt(ctx, client, probe)
		if a.OK && c.opts.EchoURL != "" {
			echo, ok := ParseEcho(body)
			if !ok {
				a.OK = false
				a.Error = "echo answer has no IP"
			} else {
				a.ExitIP = echo.IP
				if res.Geo == nil || res.Geo.IP != echo.IP {
					e := echo
					res.Geo = &e
				}
				if !seen[echo.IP] {
					seen[echo.IP] = true
					res.ExitIPs = append(res.ExitIPs, echo.IP)
				}
			}
		}
		if a.OK {
			res.Successes++
		} else {
			lastErr = a.Error
		}
		res.Tries = append(res.Tries, a)
	}
	res.UniqueIPs = len(res.ExitIPs)
	res.Rate = float64(res.Successes) / float64(c.opts.Attempts)
	res.Latency = summarise(res.Tries)

	if res.Successes == 0 {
		res.Error = lastErr
		res.Failures = append(res.Failures, "unreachable: "+lastErr)
	} else {
		c.assert(&res)
		if c.opts.TargetURL != "" {
			// One request with the target expectations (status, text) applied.
			res.Target = c.target(ctx, client)
			if !res.Target.OK {
				res.Failures = append(res.Failures, "target: "+targetReason(res.Target))
			}
		}
		if c.opts.HeadersURL != "" {
			c.anonymity(ctx, client, &res)
		}
	}
	res.Pass = res.Successes > 0 && len(res.Failures) == 0
	return res
}

func targetReason(t *TargetResult) string {
	switch {
	case t.Error != "":
		return t.Error
	case t.TextFound != nil && !*t.TextFound:
		return "expected text not found"
	default:
		return fmt.Sprintf("unexpected status %d", t.Status)
	}
}

func (c *Checker) assert(res *Result) {
	if c.opts.MinSuccessRate > 0 && res.Rate < c.opts.MinSuccessRate {
		res.Failures = append(res.Failures, fmt.Sprintf("success rate %.0f%% below %.0f%%", res.Rate*100, c.opts.MinSuccessRate*100))
	}
	if c.opts.ExpectCountry != "" {
		got := ""
		if res.Geo != nil {
			got = res.Geo.CountryCode
		}
		if got != c.opts.ExpectCountry {
			if got == "" {
				got = "unknown"
			}
			res.Failures = append(res.Failures, fmt.Sprintf("country %s, expected %s", got, c.opts.ExpectCountry))
		}
	}
	if c.opts.ExpectRotation && res.Successes >= 2 && res.UniqueIPs < 2 {
		res.Failures = append(res.Failures, fmt.Sprintf("no rotation: 1 exit IP over %d requests", res.Successes))
	}
	if c.opts.ExpectSticky && res.UniqueIPs > 1 {
		res.Failures = append(res.Failures, fmt.Sprintf("not sticky: %d exit IPs over %d requests", res.UniqueIPs, res.Successes))
	}
}

func (c *Checker) client(p proxy.Proxy) *http.Client {
	dialer := &net.Dialer{Timeout: c.opts.Timeout, KeepAlive: -1}
	tr := &http.Transport{
		DisableKeepAlives:     true, // a fresh connection per attempt, so rotation is observable
		TLSHandshakeTimeout:   c.opts.Timeout,
		ResponseHeaderTimeout: c.opts.Timeout,
		ForceAttemptHTTP2:     false,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: c.opts.Insecure}, //nolint:gosec // opt-in flag
		DialContext:           dialer.DialContext,
	}
	switch p.Protocol {
	case proxy.SOCKS4:
		tr.DialContext = socks4Dialer{proxyAddr: p.Address(), userID: p.Username, dial: dialer.DialContext}.DialContext
	default: // http, https, socks5 are handled natively by net/http
		tr.Proxy = http.ProxyURL(p.URL())
	}
	return &http.Client{
		Transport: tr,
		Timeout:   c.opts.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
}

const maxBody = 2 << 20

type timing struct {
	start, connStart, connDone, firstByte time.Time
}

func (c *Checker) do(ctx context.Context, client *http.Client, target string) (status int, body []byte, t timing, err error) {
	reqCtx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()
	trace := &httptrace.ClientTrace{
		ConnectStart:         func(string, string) { t.connStart = time.Now() },
		ConnectDone:          func(string, string, error) { t.connDone = time.Now() },
		GotFirstResponseByte: func() { t.firstByte = time.Now() },
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(reqCtx, trace), http.MethodGet, target, nil)
	if err != nil {
		return 0, nil, t, err
	}
	req.Header.Set("User-Agent", c.opts.UserAgent)
	req.Header.Set("Accept", "application/json, text/plain;q=0.9, */*;q=0.8")
	t.start = time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, t, err
	}
	defer resp.Body.Close()
	body, err = io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return resp.StatusCode, body, t, err
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func (c *Checker) attempt(ctx context.Context, client *http.Client, target string) (Attempt, []byte) {
	var a Attempt
	var body []byte
	for try := 0; try <= c.opts.Retries; try++ {
		status, b, t, err := c.do(ctx, client, target)
		a = Attempt{Status: status, TotalMs: ms(time.Since(t.start))}
		if !t.connStart.IsZero() && !t.connDone.IsZero() {
			a.ConnectMs = ms(t.connDone.Sub(t.connStart))
		}
		if !t.firstByte.IsZero() {
			a.TTFBMs = ms(t.firstByte.Sub(t.start))
		}
		if err != nil {
			a.Error = describe(err)
			if ctx.Err() != nil {
				break
			}
			continue // transport error: retry
		}
		body = b
		if status >= 200 && status < 400 {
			a.OK = true
		} else {
			a.Error = fmt.Sprintf("HTTP %d", status)
		}
		break
	}
	return a, body
}

func (c *Checker) target(ctx context.Context, client *http.Client) *TargetResult {
	tr := &TargetResult{URL: c.opts.TargetURL}
	status, body, t, err := c.do(ctx, client, c.opts.TargetURL)
	tr.TotalMs = ms(time.Since(t.start))
	if err != nil {
		tr.Error = describe(err)
		return tr
	}
	tr.Status = status
	tr.Bytes = len(body)
	statusOK := status >= 200 && status < 400
	if c.opts.ExpectStatus != 0 {
		statusOK = status == c.opts.ExpectStatus
	}
	tr.OK = statusOK
	if c.opts.ExpectText != "" {
		found := strings.Contains(string(body), c.opts.ExpectText)
		tr.TextFound = &found
		tr.OK = tr.OK && found
	}
	return tr
}

func (c *Checker) anonymity(ctx context.Context, client *http.Client, res *Result) {
	status, body, _, err := c.do(ctx, client, c.opts.HeadersURL)
	if err != nil || status < 200 || status >= 300 {
		return
	}
	level, leaked, ok := ClassifyAnonymity(body, c.opts.RealIP)
	if ok {
		res.Anonymity = level
		res.Leaked = leaked
	}
}

// describe shortens transport errors to something readable in a table.
func describe(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()):
		return "timeout"
	case errors.Is(err, errSOCKS4Rejected):
		return "socks4 request rejected"
	}
	s := err.Error()
	low := strings.ToLower(s)
	switch {
	case strings.Contains(low, "proxy authentication required") || strings.Contains(low, "407"):
		return "proxy authentication failed (407)"
	case strings.Contains(low, "connection refused") || strings.Contains(low, "actively refused"):
		return "connection refused"
	case strings.Contains(low, "no such host"):
		return "proxy host not found"
	case strings.Contains(low, "username/password authentication failed") || strings.Contains(low, "authentication failed"):
		return "proxy authentication failed"
	case strings.Contains(low, "connection reset"):
		return "connection reset"
	}
	if i := strings.LastIndex(s, ": "); i > 0 && len(s) > 120 {
		s = s[i+2:]
	}
	return s
}
