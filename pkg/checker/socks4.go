package checker

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// socks4Dialer dials through a SOCKS4 proxy. Hostnames that are not IPv4
// literals are sent with the SOCKS4a extension, so the proxy resolves them.
type socks4Dialer struct {
	proxyAddr string
	userID    string
	dial      func(ctx context.Context, network, addr string) (net.Conn, error)
}

var errSOCKS4Rejected = errors.New("socks4: request rejected by the proxy")

func (d socks4Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" {
		return nil, fmt.Errorf("socks4: unsupported network %q", network)
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("socks4: bad port %q", portStr)
	}
	conn, err := d.dial(ctx, "tcp", d.proxyAddr)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	req := []byte{4, 1, 0, 0}
	binary.BigEndian.PutUint16(req[2:], uint16(port))
	ip := net.ParseIP(host).To4()
	useHostname := ip == nil
	if useHostname {
		ip = net.IPv4(0, 0, 0, 1).To4() // SOCKS4a marker
	}
	req = append(req, ip...)
	req = append(req, []byte(d.userID)...)
	req = append(req, 0)
	if useHostname {
		req = append(req, []byte(host)...)
		req = append(req, 0)
	}
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks4: %w", err)
	}
	var resp [8]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks4: reading reply: %w", err)
	}
	if resp[1] != 0x5a {
		conn.Close()
		return nil, fmt.Errorf("%w (code 0x%02x)", errSOCKS4Rejected, resp[1])
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}
