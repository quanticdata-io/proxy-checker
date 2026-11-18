// Package proxy parses proxy strings in the formats proxy providers and
// proxy lists commonly use, and turns them into URLs.
//
// Accepted shapes:
//
//	host:port
//	user:pass@host:port
//	host:port:user:pass
//	scheme://host:port
//	scheme://user:pass@host:port
//
// Supported schemes: http, https (TLS to the proxy), socks4, socks4a, socks5, socks5h.
package proxy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Protocol is the protocol spoken to the proxy.
type Protocol string

// Supported protocols.
const (
	HTTP   Protocol = "http"
	HTTPS  Protocol = "https"
	SOCKS4 Protocol = "socks4"
	SOCKS5 Protocol = "socks5"
)

// Proxy is one parsed proxy endpoint.
type Proxy struct {
	Protocol Protocol
	Host     string
	Port     int
	Username string
	Password string
	// HasAuth is true when the string carried credentials (the password may be empty).
	HasAuth bool
	// Raw is the input line, trimmed.
	Raw string
}

// ErrInvalid is wrapped by every parse error.
var ErrInvalid = errors.New("invalid proxy string")

// Address returns host:port, bracketing IPv6 literals.
func (p Proxy) Address() string {
	return net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
}

// URL returns the proxy as a URL. SOCKS5 uses the socks5h scheme only when
// requested by the caller; the default keeps "socks5".
func (p Proxy) URL() *url.URL {
	u := &url.URL{Scheme: string(p.Protocol), Host: p.Address()}
	if p.HasAuth {
		u.User = url.UserPassword(p.Username, p.Password)
	}
	return u
}

// String returns the proxy as a URL string, credentials included.
func (p Proxy) String() string { return p.URL().String() }

// Redacted returns the proxy as a URL string with the password masked.
func (p Proxy) Redacted() string {
	if !p.HasAuth {
		return p.URL().String()
	}
	u := p.URL()
	u.User = url.UserPassword(p.Username, "xxxxx")
	return u.String()
}

func parsePort(s, line string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("%w: bad port %q in %q", ErrInvalid, s, line)
	}
	return n, nil
}

func normalizeScheme(s string) (Protocol, bool) {
	switch strings.ToLower(s) {
	case "http":
		return HTTP, true
	case "https":
		return HTTPS, true
	case "socks4", "socks4a":
		return SOCKS4, true
	case "socks5", "socks5h", "socks":
		return SOCKS5, true
	}
	return "", false
}

// ParseProtocol validates a protocol name (http, https, socks4, socks5 and aliases).
func ParseProtocol(s string) (Protocol, error) {
	p, ok := normalizeScheme(s)
	if !ok {
		return "", fmt.Errorf("unsupported protocol %q (use http, https, socks4 or socks5)", s)
	}
	return p, nil
}

// Parse parses one proxy string. def is the protocol assumed when the string has no scheme.
func Parse(line string, def Protocol) (Proxy, error) {
	in := strings.TrimSpace(line)
	if in == "" {
		return Proxy{}, fmt.Errorf("%w: empty", ErrInvalid)
	}
	p := Proxy{Protocol: def, Raw: in}
	rest := in
	if i := strings.Index(rest, "://"); i > 0 {
		proto, ok := normalizeScheme(rest[:i])
		if !ok {
			return Proxy{}, fmt.Errorf("%w: unsupported scheme %q in %q", ErrInvalid, rest[:i], in)
		}
		p.Protocol = proto
		rest = strings.TrimRight(rest[i+3:], "/")
	}

	if at := strings.LastIndex(rest, "@"); at >= 0 && validHostPort(rest[at+1:]) {
		cred, hostPort := rest[:at], rest[at+1:]
		host, port, _ := net.SplitHostPort(hostPort)
		p.Host = host
		p.Port, _ = parsePort(port, in)
		p.HasAuth = true
		if c := strings.Index(cred, ":"); c >= 0 {
			p.Username, p.Password = unescape(cred[:c]), unescape(cred[c+1:])
		} else {
			p.Username = unescape(cred)
		}
		return p, nil
	}

	if strings.HasPrefix(rest, "[") { // [ipv6]:port
		host, port, err := net.SplitHostPort(rest)
		if err != nil {
			return Proxy{}, fmt.Errorf("%w: bad host:port in %q", ErrInvalid, in)
		}
		p.Host = host
		p.Port, err = parsePort(port, in)
		return p, err
	}

	parts := strings.Split(rest, ":")
	switch {
	case len(parts) == 2:
		p.Host = parts[0]
		var err error
		p.Port, err = parsePort(parts[1], in)
		if err != nil {
			return Proxy{}, err
		}
	case len(parts) >= 4:
		// host:port:user:pass (the password may itself contain ':')
		p.Host = parts[0]
		var err error
		if p.Port, err = parsePort(parts[1], in); err != nil {
			return Proxy{}, err
		}
		p.HasAuth = true
		p.Username = parts[2]
		p.Password = strings.Join(parts[3:], ":")
	default:
		return Proxy{}, fmt.Errorf("%w: unrecognised format %q", ErrInvalid, in)
	}
	if p.Host == "" {
		return Proxy{}, fmt.Errorf("%w: empty host in %q", ErrInvalid, in)
	}
	return p, nil
}

// validHostPort reports whether s is host:port with a usable port. It lets
// host:port:user:pass strings whose password contains '@' parse correctly.
func validHostPort(s string) bool {
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" || strings.ContainsAny(host, "/@") {
		return false
	}
	_, err = parsePort(port, s)
	return err == nil
}

func unescape(s string) string {
	if u, err := url.PathUnescape(s); err == nil {
		return u
	}
	return s
}

// LineError reports a line of a list that could not be parsed.
type LineError struct {
	Line int
	Err  error
}

func (e LineError) Error() string { return fmt.Sprintf("line %d: %v", e.Line, e.Err) }

// ReadList reads one proxy per line. Blank lines and lines starting with '#'
// are skipped. Unparseable lines are returned as LineErrors, not fatal.
func ReadList(r io.Reader, def Protocol) ([]Proxy, []LineError, error) {
	var out []Proxy
	var bad []LineError
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, err := Parse(line, def)
		if err != nil {
			bad = append(bad, LineError{Line: n, Err: err})
			continue
		}
		out = append(out, p)
	}
	return out, bad, sc.Err()
}
