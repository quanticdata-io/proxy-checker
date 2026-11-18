package checker_test

import (
	"context"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quanticdata-io/proxy-checker/internal/testutil"
	"github.com/quanticdata-io/proxy-checker/pkg/checker"
	"github.com/quanticdata-io/proxy-checker/pkg/proxy"
)

type lab struct {
	echo  *httptest.Server
	proxy *httptest.Server
	hp    *testutil.HTTPProxy
}

func newLab(t *testing.T, hp *testutil.HTTPProxy) lab {
	t.Helper()
	echo := httptest.NewServer(testutil.EchoHandler())
	t.Cleanup(echo.Close)
	ps := httptest.NewServer(hp)
	t.Cleanup(ps.Close)
	return lab{echo: echo, proxy: ps, hp: hp}
}

func (l lab) proxyLine(cred string) string {
	host := strings.TrimPrefix(l.proxy.URL, "http://")
	if cred != "" {
		return cred + "@" + host
	}
	return host
}

func mustParse(t *testing.T, line string) proxy.Proxy {
	t.Helper()
	p, err := proxy.Parse(line, proxy.HTTP)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func opts(echoURL string) checker.Options {
	o := checker.DefaultOptions()
	o.EchoURL = echoURL
	o.Timeout = 5 * time.Second
	o.Retries = 0
	return o
}

func check(t *testing.T, o checker.Options, line string) checker.Result {
	t.Helper()
	c, err := checker.New(o)
	if err != nil {
		t.Fatal(err)
	}
	return c.Check(context.Background(), mustParse(t, line))
}

func TestHTTPProxyWithAuth(t *testing.T) {
	l := newLab(t, &testutil.HTTPProxy{Username: "user", Password: "p@ss", Exit: testutil.ExitSticky, Country: "DE"})
	r := check(t, opts(l.echo.URL+"/ip"), l.proxyLine("user:p%40ss"))
	if !r.Pass || r.Successes != 3 || r.Rate != 1 {
		t.Fatalf("result = %+v", r)
	}
	if r.Geo == nil || r.Geo.IP != "203.0.113.10" || r.Geo.CountryCode != "DE" || r.Geo.Country != "Germany" {
		t.Fatalf("geo = %+v", r.Geo)
	}
	if r.Latency == nil || r.Latency.P50 <= 0 || r.Latency.P95 < r.Latency.P50 {
		t.Fatalf("latency = %+v", r.Latency)
	}
	if strings.Contains(r.Proxy, "p%40ss") || !strings.Contains(r.Proxy, "xxxxx") {
		t.Fatalf("password not masked: %s", r.Proxy)
	}
}

func TestHTTPProxyBadCredentials(t *testing.T) {
	l := newLab(t, &testutil.HTTPProxy{Username: "user", Password: "right"})
	r := check(t, opts(l.echo.URL+"/ip"), l.proxyLine("user:wrong"))
	if r.Pass || r.Successes != 0 {
		t.Fatalf("expected failure, got %+v", r)
	}
	if !strings.Contains(r.Error, "407") {
		t.Fatalf("error = %q", r.Error)
	}
}

func TestHTTPSViaConnect(t *testing.T) {
	echo := httptest.NewTLSServer(testutil.EchoHandler())
	defer echo.Close()
	ps := httptest.NewServer(&testutil.HTTPProxy{})
	defer ps.Close()
	o := opts(echo.URL + "/ip")
	o.Insecure = true // httptest certificate
	r := check(t, o, strings.TrimPrefix(ps.URL, "http://"))
	if !r.Pass || r.Geo == nil || r.Geo.IP != "127.0.0.1" {
		t.Fatalf("result = %+v", r)
	}
}

func TestDeadProxy(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	echo := httptest.NewServer(testutil.EchoHandler())
	defer echo.Close()
	r := check(t, opts(echo.URL+"/ip"), addr)
	if r.Pass || r.Error == "" || r.Latency != nil {
		t.Fatalf("result = %+v", r)
	}
}

func TestExpectCountry(t *testing.T) {
	l := newLab(t, &testutil.HTTPProxy{Country: "IT"})
	o := opts(l.echo.URL + "/ip")
	o.ExpectCountry = "us"
	r := check(t, o, l.proxyLine(""))
	if r.Pass || len(r.Failures) != 1 || !strings.Contains(r.Failures[0], "country IT, expected US") {
		t.Fatalf("result = %+v", r)
	}
	o.ExpectCountry = "it"
	if r := check(t, o, l.proxyLine("")); !r.Pass {
		t.Fatalf("result = %+v", r)
	}
}

func TestRotation(t *testing.T) {
	l := newLab(t, &testutil.HTTPProxy{Exit: testutil.ExitRotating})
	o := opts(l.echo.URL + "/ip")
	o.Attempts = 5
	o.ExpectRotation = true
	r := check(t, o, l.proxyLine(""))
	if !r.Pass || r.UniqueIPs != 5 {
		t.Fatalf("result = %+v", r)
	}
	o.ExpectRotation = false
	o.ExpectSticky = true
	if r := check(t, o, l.proxyLine("")); r.Pass || !strings.Contains(strings.Join(r.Failures, ";"), "not sticky") {
		t.Fatalf("rotating gateway passed the sticky check: %+v", r)
	}
}

func TestSticky(t *testing.T) {
	l := newLab(t, &testutil.HTTPProxy{Exit: testutil.ExitSticky})
	o := opts(l.echo.URL + "/ip")
	o.Attempts = 4
	o.ExpectSticky = true
	if r := check(t, o, l.proxyLine("")); !r.Pass || r.UniqueIPs != 1 {
		t.Fatalf("result = %+v", r)
	}
	o.ExpectSticky = false
	o.ExpectRotation = true
	if r := check(t, o, l.proxyLine("")); r.Pass || !strings.Contains(strings.Join(r.Failures, ";"), "no rotation") {
		t.Fatalf("sticky session passed the rotation check: %+v", r)
	}
}

func TestEchoFormats(t *testing.T) {
	l := newLab(t, &testutil.HTTPProxy{Exit: testutil.ExitSticky, Country: "DE"})
	for _, path := range []string{"/ip", "/flat", "/text"} {
		r := check(t, opts(l.echo.URL+path), l.proxyLine(""))
		if !r.Pass || r.Geo == nil || r.Geo.IP != "203.0.113.10" {
			t.Fatalf("%s: result = %+v", path, r)
		}
	}
}

func TestTarget(t *testing.T) {
	l := newLab(t, &testutil.HTTPProxy{})
	o := opts(l.echo.URL + "/ip")
	o.TargetURL = l.echo.URL + "/page"
	o.ExpectText = "Example Domain"
	if r := check(t, o, l.proxyLine("")); !r.Pass || r.Target == nil || !r.Target.OK || r.Target.Bytes == 0 {
		t.Fatalf("result = %+v", r)
	}
	o.ExpectText = "not on the page"
	if r := check(t, o, l.proxyLine("")); r.Pass || r.Target.TextFound == nil || *r.Target.TextFound {
		t.Fatalf("result = %+v", r)
	}
	o.ExpectText = ""
	o.TargetURL = l.echo.URL + "/status/403"
	if r := check(t, o, l.proxyLine("")); r.Pass || r.Target.Status != 403 {
		t.Fatalf("result = %+v", r)
	}
}

func TestTargetOnly(t *testing.T) {
	l := newLab(t, &testutil.HTTPProxy{})
	o := opts("")
	o.TargetURL = l.echo.URL + "/page"
	r := check(t, o, l.proxyLine(""))
	if !r.Pass || r.Geo != nil || r.Successes != 3 {
		t.Fatalf("result = %+v", r)
	}
}

func TestAnonymity(t *testing.T) {
	cases := []struct {
		add  map[string]string
		real string
		want string
	}{
		{nil, "198.51.100.77", checker.AnonymityElite},
		{map[string]string{"Via": "1.1 test-proxy"}, "198.51.100.77", checker.AnonymityAnonymous},
		{map[string]string{"X-Forwarded-For": "198.51.100.77"}, "198.51.100.77", checker.AnonymityTransparent},
	}
	for _, c := range cases {
		l := newLab(t, &testutil.HTTPProxy{AddHeaders: c.add})
		o := opts(l.echo.URL + "/ip")
		o.HeadersURL = l.echo.URL + "/headers"
		o.RealIP = c.real
		if r := check(t, o, l.proxyLine("")); r.Anonymity != c.want {
			t.Errorf("headers %v: anonymity = %q, want %q", c.add, r.Anonymity, c.want)
		}
	}
}

func TestSOCKS5(t *testing.T) {
	echo := httptest.NewServer(testutil.EchoHandler())
	defer echo.Close()
	s, err := testutil.ListenSOCKS("127.0.0.1:0", "u", "secret")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if r := check(t, opts(echo.URL+"/ip"), "socks5://u:secret@"+s.Addr()); !r.Pass || r.Geo.IP != "127.0.0.1" {
		t.Fatalf("result = %+v", r)
	}
	if r := check(t, opts(echo.URL+"/ip"), "socks5://u:bad@"+s.Addr()); r.Pass {
		t.Fatalf("bad credentials passed: %+v", r)
	}
}

func TestSOCKS4(t *testing.T) {
	echo := httptest.NewServer(testutil.EchoHandler())
	defer echo.Close()
	s, err := testutil.ListenSOCKS("127.0.0.1:0", "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// IPv4 literal target.
	if r := check(t, opts(echo.URL+"/ip"), "socks4://"+s.Addr()); !r.Pass {
		t.Fatalf("result = %+v", r)
	}
	// Hostname target: SOCKS4a.
	host := strings.Replace(echo.URL, "127.0.0.1", "localhost", 1)
	if r := check(t, opts(host+"/ip"), "socks4://"+s.Addr()); !r.Pass {
		t.Fatalf("socks4a result = %+v", r)
	}
}

func TestRunKeepsOrderAndConcurrency(t *testing.T) {
	l := newLab(t, &testutil.HTTPProxy{})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	lines := []string{l.proxyLine(""), dead, l.proxyLine(""), dead}
	var ps []proxy.Proxy
	for _, s := range lines {
		ps = append(ps, mustParse(t, s))
	}
	o := opts(l.echo.URL + "/ip")
	o.Attempts = 1
	o.Concurrency = 3
	c, _ := checker.New(o)
	calls := 0
	res := c.Run(context.Background(), ps, func(int, checker.Result) { calls++ })
	if calls != 4 {
		t.Fatalf("callback calls = %d", calls)
	}
	want := []bool{true, false, true, false}
	for i, r := range res {
		if r.Pass != want[i] {
			t.Errorf("result %d pass = %v, want %v", i, r.Pass, want[i])
		}
	}
	s := checker.Summarise(res)
	if s.Passed != 2 || s.Failed != 2 || s.PassRate != 50 {
		t.Fatalf("summary = %+v", s)
	}
}

func TestNewValidates(t *testing.T) {
	bad := []checker.Options{
		{EchoURL: "", TargetURL: ""},
		{EchoURL: "ftp://x"},
		{EchoURL: "http://x", ExpectRotation: true, ExpectSticky: true, Attempts: 3},
		{EchoURL: "http://x", ExpectRotation: true, Attempts: 1},
		{TargetURL: "http://x", ExpectCountry: "US"},
	}
	for i, o := range bad {
		if _, err := checker.New(o); err == nil {
			t.Errorf("case %d: expected an error", i)
		}
	}
}

func TestParseEcho(t *testing.T) {
	cases := map[string]checker.Echo{
		`{"type":"response","payload":{"ip":"203.0.113.10","countryCode":"US","country":"United States","city":"New York"}}`: {IP: "203.0.113.10", CountryCode: "US", Country: "United States", City: "New York"},
		`{"query":"198.51.100.1","countryCode":"DE","country":"Germany","regionName":"Berlin"}`:                              {IP: "198.51.100.1", CountryCode: "DE", Country: "Germany", Region: "Berlin"},
		`{"ip":"198.51.100.2","country":"it"}`: {IP: "198.51.100.2", CountryCode: "IT", Country: "it"},
		`{"origin":"198.51.100.3, 10.0.0.1"}`:  {IP: "198.51.100.3"},
		"2001:db8::7\n":                        {IP: "2001:db8::7"},
	}
	for in, want := range cases {
		got, ok := checker.ParseEcho([]byte(in))
		if !ok || got != want {
			t.Errorf("ParseEcho(%s) = %+v, %v; want %+v", in, got, ok, want)
		}
	}
	if _, ok := checker.ParseEcho([]byte("<html>blocked</html>")); ok {
		t.Error("HTML must not parse as an echo")
	}
}
