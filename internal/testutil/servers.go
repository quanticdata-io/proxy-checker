// Package testutil provides in-process proxy and echo servers for tests and
// for the local lab in examples/locallab. Nothing here talks to the internet.
package testutil

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Headers the test proxies inject so the echo server can simulate exits.
const (
	HeaderExitIP  = "X-Test-Exit-Ip"
	HeaderCountry = "X-Test-Country"
)

// ---- Echo server -----------------------------------------------------------

// EchoHandler serves:
//
//	/ip       QuanticData-style envelope with the exit IP and geo
//	/flat     flat JSON {"ip","country_code","city"}
//	/text     the exit IP as plain text
//	/headers  httpbin-style {"headers":{...}} with the received headers
//	/page     an HTML page containing "Example Domain"
//	/status/N answers with status N
func EchoHandler() http.Handler {
	mux := http.NewServeMux()
	exit := func(r *http.Request) (string, string) {
		ip := r.Header.Get(HeaderExitIP)
		if ip == "" {
			ip, _, _ = net.SplitHostPort(r.RemoteAddr)
		}
		cc := r.Header.Get(HeaderCountry)
		if cc == "" {
			cc = "US"
		}
		return ip, cc
	}
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("/ip", func(w http.ResponseWriter, r *http.Request) {
		ip, cc := exit(r)
		writeJSON(w, map[string]any{
			"type": "response", "message": "Success", "pagination": map[string]any{},
			"payload": map[string]any{
				"ip": ip, "countryCode": cc, "country": countryName(cc), "region": "Test Region", "city": "Test City",
				"timezone": "UTC", "tor": false, "precision": "city", "viaCloudflare": false, "source": "cloudflare",
			},
		})
	})
	mux.HandleFunc("/flat", func(w http.ResponseWriter, r *http.Request) {
		ip, cc := exit(r)
		writeJSON(w, map[string]any{"ip": ip, "country_code": strings.ToLower(cc), "city": "Test City"})
	})
	mux.HandleFunc("/text", func(w http.ResponseWriter, r *http.Request) {
		ip, _ := exit(r)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, ip)
	})
	mux.HandleFunc("/headers", func(w http.ResponseWriter, r *http.Request) {
		h := map[string]string{}
		for k, v := range r.Header {
			if k == HeaderExitIP || k == HeaderCountry {
				continue
			}
			h[k] = strings.Join(v, ", ")
		}
		writeJSON(w, map[string]any{"headers": h})
	})
	mux.HandleFunc("/page", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><head><title>Example Domain</title></head><body><h1>Example Domain</h1></body></html>")
	})
	mux.HandleFunc("/status/", func(w http.ResponseWriter, r *http.Request) {
		code, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/status/"))
		if err != nil || code < 100 || code > 599 {
			code = 400
		}
		w.WriteHeader(code)
	})
	return mux
}

func countryName(cc string) string {
	switch cc {
	case "US":
		return "United States"
	case "DE":
		return "Germany"
	case "IT":
		return "Italy"
	}
	return cc
}

// ---- HTTP proxy ------------------------------------------------------------

// ExitMode decides which exit IP the HTTP proxy simulates per request.
type ExitMode int

// Exit modes.
const (
	ExitReal     ExitMode = iota // no header: the echo sees the real remote address
	ExitSticky                   // always 203.0.113.10
	ExitRotating                 // 203.0.113.1, .2, .3, ... one per request
)

// HTTPProxy is a forward proxy supporting absolute-form requests and CONNECT.
type HTTPProxy struct {
	Username, Password string
	Exit               ExitMode
	Country            string            // injected as the simulated exit country
	AddHeaders         map[string]string // added to forwarded plain-HTTP requests (anonymity tests)
	Requests           atomic.Int64
}

var forwardTransport = &http.Transport{Proxy: nil, DisableKeepAlives: true}

func (p *HTTPProxy) authorized(r *http.Request) bool {
	if p.Username == "" {
		return true
	}
	h := r.Header.Get("Proxy-Authorization")
	const prefix = "Basic "
	if !strings.HasPrefix(h, prefix) {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(h[len(prefix):])
	return err == nil && string(raw) == p.Username+":"+p.Password
}

func (p *HTTPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n := p.Requests.Add(1)
	if !p.authorized(r) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="test"`)
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	}
	if r.Method == http.MethodConnect {
		p.tunnel(w, r)
		return
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.Header.Del("Proxy-Authorization")
	out.Header.Del("Proxy-Connection")
	switch p.Exit {
	case ExitSticky:
		out.Header.Set(HeaderExitIP, "203.0.113.10")
	case ExitRotating:
		out.Header.Set(HeaderExitIP, fmt.Sprintf("203.0.113.%d", (n-1)%250+1))
	}
	if p.Country != "" {
		out.Header.Set(HeaderCountry, p.Country)
	}
	for k, v := range p.AddHeaders {
		out.Header.Set(k, v)
	}
	resp, err := forwardTransport.RoundTrip(out)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (p *HTTPProxy) tunnel(w http.ResponseWriter, r *http.Request) {
	upstream, err := net.Dial("tcp", r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	client, buf, err := hj.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	_, _ = client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if buf.Reader.Buffered() > 0 {
		pending, _ := buf.Peek(buf.Reader.Buffered())
		_, _ = upstream.Write(pending)
	}
	pipe(client, upstream)
}

func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if tc, ok := dst.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	a.Close()
	b.Close()
}

// ---- SOCKS servers ---------------------------------------------------------

// SOCKSServer is a minimal SOCKS4/4a and SOCKS5 (no auth or user/pass) server.
type SOCKSServer struct {
	Username, Password string // SOCKS5 only; empty means no authentication
	Listener           net.Listener
	Requests           atomic.Int64
}

// ListenSOCKS starts a SOCKS server on 127.0.0.1 (port 0 = random).
func ListenSOCKS(addr, user, pass string) (*SOCKSServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s := &SOCKSServer{Username: user, Password: pass, Listener: ln}
	go s.serve()
	return s, nil
}

// Addr is host:port of the server.
func (s *SOCKSServer) Addr() string { return s.Listener.Addr().String() }

// Close stops the server.
func (s *SOCKSServer) Close() error { return s.Listener.Close() }

func (s *SOCKSServer) serve() {
	for {
		c, err := s.Listener.Accept()
		if err != nil {
			return
		}
		go s.handle(c)
	}
}

func (s *SOCKSServer) handle(c net.Conn) {
	s.Requests.Add(1)
	br := bufio.NewReader(c)
	ver, err := br.ReadByte()
	if err != nil {
		c.Close()
		return
	}
	var target string
	switch ver {
	case 4:
		target, err = socks4Request(br)
		if err != nil {
			_, _ = c.Write([]byte{0, 0x5b, 0, 0, 0, 0, 0, 0})
			c.Close()
			return
		}
		up, derr := net.Dial("tcp", target)
		if derr != nil {
			_, _ = c.Write([]byte{0, 0x5b, 0, 0, 0, 0, 0, 0})
			c.Close()
			return
		}
		_, _ = c.Write([]byte{0, 0x5a, 0, 0, 0, 0, 0, 0})
		pipe(&bufferedConn{Conn: c, r: br}, up)
	case 5:
		if err := s.socks5Handshake(br, c); err != nil {
			c.Close()
			return
		}
		target, err = socks5Request(br)
		if err != nil {
			_, _ = c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
			c.Close()
			return
		}
		up, derr := net.Dial("tcp", target)
		if derr != nil {
			_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
			c.Close()
			return
		}
		_, _ = c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
		pipe(&bufferedConn{Conn: c, r: br}, up)
	default:
		c.Close()
	}
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func readCString(br *bufio.Reader) (string, error) {
	s, err := br.ReadString(0)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(s, "\x00"), nil
}

func socks4Request(br *bufio.Reader) (string, error) {
	var hdr [7]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return "", err
	}
	if hdr[0] != 1 {
		return "", errors.New("only CONNECT")
	}
	port := binary.BigEndian.Uint16(hdr[1:3])
	ip := net.IP(hdr[3:7])
	if _, err := readCString(br); err != nil { // user id
		return "", err
	}
	host := ip.String()
	if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0 { // SOCKS4a
		h, err := readCString(br)
		if err != nil {
			return "", err
		}
		host = h
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func (s *SOCKSServer) socks5Handshake(br *bufio.Reader, c net.Conn) error {
	n, err := br.ReadByte()
	if err != nil {
		return err
	}
	methods := make([]byte, n)
	if _, err := io.ReadFull(br, methods); err != nil {
		return err
	}
	want := byte(0)
	if s.Username != "" {
		want = 2
	}
	offered := false
	for _, m := range methods {
		if m == want {
			offered = true
		}
	}
	if !offered {
		_, _ = c.Write([]byte{5, 0xff})
		return errors.New("no acceptable method")
	}
	_, _ = c.Write([]byte{5, want})
	if want == 0 {
		return nil
	}
	if v, _ := br.ReadByte(); v != 1 {
		return errors.New("bad auth version")
	}
	ul, _ := br.ReadByte()
	u := make([]byte, ul)
	if _, err := io.ReadFull(br, u); err != nil {
		return err
	}
	pl, _ := br.ReadByte()
	pw := make([]byte, pl)
	if _, err := io.ReadFull(br, pw); err != nil {
		return err
	}
	if string(u) != s.Username || string(pw) != s.Password {
		_, _ = c.Write([]byte{1, 1})
		return errors.New("bad credentials")
	}
	_, _ = c.Write([]byte{1, 0})
	return nil
}

func socks5Request(br *bufio.Reader) (string, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return "", err
	}
	if hdr[0] != 5 || hdr[1] != 1 {
		return "", errors.New("only CONNECT")
	}
	var host string
	switch hdr[3] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case 3:
		l, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		b := make([]byte, l)
		if _, err := io.ReadFull(br, b); err != nil {
			return "", err
		}
		host = string(b)
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	default:
		return "", errors.New("bad address type")
	}
	var pb [2]byte
	if _, err := io.ReadFull(br, pb[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(pb[:])))), nil
}
