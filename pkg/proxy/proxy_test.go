package proxy

import (
	"errors"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	cases := []struct {
		in   string
		want Proxy
	}{
		{"gw.example.net:8080", Proxy{Protocol: HTTP, Host: "gw.example.net", Port: 8080}},
		{"user:pass@gw.example.net:8080", Proxy{Protocol: HTTP, Host: "gw.example.net", Port: 8080, Username: "user", Password: "pass", HasAuth: true}},
		{"gw.example.net:8080:user:pass", Proxy{Protocol: HTTP, Host: "gw.example.net", Port: 8080, Username: "user", Password: "pass", HasAuth: true}},
		{"203.0.113.7:9000:u:p:a:ss", Proxy{Protocol: HTTP, Host: "203.0.113.7", Port: 9000, Username: "u", Password: "p:a:ss", HasAuth: true}},
		{"http://user:pass@gw.example.net:8080/", Proxy{Protocol: HTTP, Host: "gw.example.net", Port: 8080, Username: "user", Password: "pass", HasAuth: true}},
		{"https://gw.example.net:443", Proxy{Protocol: HTTPS, Host: "gw.example.net", Port: 443}},
		{"socks5://u:p@gw.example.net:1080", Proxy{Protocol: SOCKS5, Host: "gw.example.net", Port: 1080, Username: "u", Password: "p", HasAuth: true}},
		{"socks5h://gw.example.net:1080", Proxy{Protocol: SOCKS5, Host: "gw.example.net", Port: 1080}},
		{"socks4://198.51.100.2:1080", Proxy{Protocol: SOCKS4, Host: "198.51.100.2", Port: 1080}},
		{"u:p%40ss@gw.example.net:1", Proxy{Protocol: HTTP, Host: "gw.example.net", Port: 1, Username: "u", Password: "p@ss", HasAuth: true}},
		{"u:p@ss@gw.example.net:1", Proxy{Protocol: HTTP, Host: "gw.example.net", Port: 1, Username: "u", Password: "p@ss", HasAuth: true}},
		{"[2001:db8::1]:8080", Proxy{Protocol: HTTP, Host: "2001:db8::1", Port: 8080}},
		{"user_8c21-country-us-sid-k3f9-ttl-10m:pw@gw.example.net:8080", Proxy{Protocol: HTTP, Host: "gw.example.net", Port: 8080, Username: "user_8c21-country-us-sid-k3f9-ttl-10m", Password: "pw", HasAuth: true}},
	}
	for _, c := range cases {
		got, err := Parse(c.in, HTTP)
		if err != nil {
			t.Fatalf("Parse(%q): %v", c.in, err)
		}
		c.want.Raw = strings.TrimSpace(c.in)
		if got != c.want {
			t.Errorf("Parse(%q)\n got %+v\nwant %+v", c.in, got, c.want)
		}
	}
}

func TestParseDefaultProtocol(t *testing.T) {
	p, err := Parse("h.example:1080", SOCKS5)
	if err != nil || p.Protocol != SOCKS5 {
		t.Fatalf("got %+v, %v", p, err)
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{"", "h.example", "u:p@h.example", "ftp://h.example:21", "h.example:0", "h.example:70000", "a:b:c", ":8080"} {
		if _, err := Parse(in, HTTP); !errors.Is(err, ErrInvalid) {
			t.Errorf("Parse(%q) error = %v, want ErrInvalid", in, err)
		}
	}
}

func TestURLAndRedacted(t *testing.T) {
	p, _ := Parse("gw.example.net:8080:user:p@ss/w:rd", HTTP)
	if got, want := p.String(), "http://user:p%40ss%2Fw%3Ard@gw.example.net:8080"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	if got := p.Redacted(); strings.Contains(got, "p%40ss") || !strings.Contains(got, "user:xxxxx@") {
		t.Errorf("Redacted() leaks or misses the user: %q", got)
	}
	v6, _ := Parse("[2001:db8::1]:8080", HTTP)
	if got := v6.String(); got != "http://[2001:db8::1]:8080" {
		t.Errorf("IPv6 String() = %q", got)
	}
}

func TestReadList(t *testing.T) {
	in := "# my list\n\nh1.example:1\nbad line\nsocks5://h2.example:2\n"
	ps, bad, err := ReadList(strings.NewReader(in), HTTP)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 2 || ps[1].Protocol != SOCKS5 {
		t.Fatalf("proxies = %+v", ps)
	}
	if len(bad) != 1 || bad[0].Line != 4 {
		t.Fatalf("bad = %+v", bad)
	}
}

func TestParseProtocol(t *testing.T) {
	for in, want := range map[string]Protocol{"http": HTTP, "HTTPS": HTTPS, "socks4a": SOCKS4, "socks5h": SOCKS5} {
		if got, err := ParseProtocol(in); err != nil || got != want {
			t.Errorf("ParseProtocol(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := ParseProtocol("ftp"); err == nil {
		t.Error("ParseProtocol(ftp) should fail")
	}
}
