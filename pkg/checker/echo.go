package checker

import (
	"encoding/json"
	"strings"
)

// Echo is what an IP echo endpoint reported about the exit of a request.
type Echo struct {
	IP          string `json:"ip,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
	Country     string `json:"country,omitempty"`
	Region      string `json:"region,omitempty"`
	City        string `json:"city,omitempty"`
	Timezone    string `json:"timezone,omitempty"`
	Tor         bool   `json:"tor,omitempty"`
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

// ParseEcho reads the JSON answer of an IP echo endpoint. It understands the
// QuanticData envelope ({"type":"response","payload":{...}}) and the flat
// shapes most echo services use (ip / origin / query, countryCode /
// country_code / country, region / regionName, city, timezone).
// A plain-text body holding only an IP address is accepted too.
func ParseEcho(body []byte) (Echo, bool) {
	text := strings.TrimSpace(string(body))
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		if ip := strings.TrimSpace(strings.SplitN(text, "\n", 2)[0]); looksLikeIP(ip) {
			return Echo{IP: ip}, true
		}
		return Echo{}, false
	}
	if p, ok := m["payload"].(map[string]any); ok {
		m = p
	} else if d, ok := m["data"].(map[string]any); ok && m["ip"] == nil {
		m = d
	}
	e := Echo{
		IP:          firstString(m, "ip", "origin", "query", "ip_address", "ipAddress", "address"),
		CountryCode: strings.ToUpper(firstString(m, "countryCode", "country_code", "countryIsoCode", "country_iso")),
		Country:     firstString(m, "country", "country_name", "countryName"),
		Region:      firstString(m, "region", "regionName", "region_name", "state"),
		City:        firstString(m, "city"),
		Timezone:    firstString(m, "timezone", "time_zone"),
	}
	if t, ok := m["tor"].(bool); ok {
		e.Tor = t
	}
	// Some services put the ISO code in "country".
	if e.CountryCode == "" && len(e.Country) == 2 {
		e.CountryCode = strings.ToUpper(e.Country)
	}
	// httpbin-style "origin" can hold "client, proxy": keep the first address.
	if i := strings.Index(e.IP, ","); i > 0 {
		e.IP = strings.TrimSpace(e.IP[:i])
	}
	return e, e.IP != ""
}

func looksLikeIP(s string) bool {
	if s == "" || len(s) > 45 {
		return false
	}
	for _, r := range s {
		if !(r == '.' || r == ':' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return strings.ContainsAny(s, ".:")
}

// forwardingHeaders are request headers a proxy adds when it reveals that a
// request was proxied (or for whom).
var forwardingHeaders = []string{
	"Via", "X-Forwarded-For", "Forwarded", "X-Real-Ip", "X-Client-Ip", "Client-Ip",
	"X-Proxy-Id", "X-Forwarded-Host", "X-Originating-Ip", "True-Client-Ip", "Proxy-Connection",
}

// Anonymity levels.
const (
	AnonymityTransparent = "transparent" // the client IP is visible to the target
	AnonymityAnonymous   = "anonymous"   // the target can tell a proxy was used
	AnonymityElite       = "elite"       // no proxy header reached the target
)

// ClassifyAnonymity inspects the headers a header-echo endpoint received
// (httpbin-style {"headers":{...}} or a flat object) and classifies the proxy.
// realIP is the client's own public IP; when empty, transparency cannot be
// detected and the result is at most "anonymous".
func ClassifyAnonymity(body []byte, realIP string) (string, []string, bool) {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return "", nil, false
	}
	if p, ok := m["payload"].(map[string]any); ok {
		m = p
	}
	if h, ok := m["headers"].(map[string]any); ok {
		m = h
	}
	lower := map[string]string{}
	for k, v := range m {
		switch vv := v.(type) {
		case string:
			lower[strings.ToLower(k)] = vv
		case []any:
			parts := make([]string, 0, len(vv))
			for _, x := range vv {
				if s, ok := x.(string); ok {
					parts = append(parts, s)
				}
			}
			lower[strings.ToLower(k)] = strings.Join(parts, ", ")
		}
	}
	var found []string
	for _, h := range forwardingHeaders {
		if _, ok := lower[strings.ToLower(h)]; ok {
			found = append(found, h)
		}
	}
	if realIP != "" {
		for _, v := range lower {
			if strings.Contains(v, realIP) {
				return AnonymityTransparent, found, true
			}
		}
	}
	if len(found) > 0 {
		return AnonymityAnonymous, found, true
	}
	return AnonymityElite, nil, true
}
