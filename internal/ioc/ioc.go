// Package ioc parses, normalises and classifies indicators.
package ioc

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Kind is an indicator type.
type Kind string

const (
	IP     Kind = "ip"
	IPPort Kind = "ip:port"
	Domain Kind = "domain"
	URL    Kind = "url"
	SHA256 Kind = "sha256"
	MD5    Kind = "md5"
)

// IOC is a normalised indicator.
type IOC struct {
	Kind  Kind
	Value string
}

// ID is the stable graph key for an indicator.
func (i IOC) ID() string { return string(i.Kind) + "|" + i.Value }

func (i IOC) String() string { return i.Value }

var (
	hexRE    = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	domainRE = regexp.MustCompile(`^(?i)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$`)
)

// Refang undoes the usual defanging: hxxp, [.], (.), [:], {.}.
func Refang(s string) string {
	r := strings.NewReplacer(
		"[.]", ".", "(.)", ".", "{.}", ".", "[dot]", ".", "(dot)", ".",
		"[:]", ":", "[://]", "://",
		"hxxp", "http", "hXXp", "http", "HXXP", "HTTP",
	)
	return strings.TrimSpace(r.Replace(s))
}

// Defang makes an indicator safe to paste into a report or chat: the last
// dot of the host becomes [.] and http becomes hxxp.
func Defang(s string) string {
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		host := u.Hostname()
		rest := strings.TrimPrefix(s, u.Scheme+"://")
		scheme := strings.Replace(u.Scheme, "http", "hxxp", 1)
		return scheme + "://" + strings.Replace(rest, host, defangHost(host), 1)
	}
	if h, p, err := net.SplitHostPort(s); err == nil {
		return defangHost(h) + ":" + p
	}
	return defangHost(s)
}

func defangHost(h string) string {
	if strings.Contains(h, ":") { // IPv6
		return h
	}
	if i := strings.LastIndex(h, "."); i >= 0 {
		return h[:i] + "[.]" + h[i+1:]
	}
	return h
}

// Parse classifies and normalises a raw indicator string.
func Parse(raw string) (IOC, error) {
	s := Refang(raw)
	if s == "" {
		return IOC{}, fmt.Errorf("empty indicator")
	}

	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			return IOC{}, fmt.Errorf("bad url %q", raw)
		}
		u.Host = strings.ToLower(u.Host)
		u.Scheme = strings.ToLower(u.Scheme)
		u.Fragment = ""
		return IOC{URL, u.String()}, nil
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return IOC{IPPort, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()).String()}, nil
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return IOC{IP, a.Unmap().String()}, nil
	}
	if hexRE.MatchString(s) {
		switch len(s) {
		case 64:
			return IOC{SHA256, strings.ToLower(s)}, nil
		case 32:
			return IOC{MD5, strings.ToLower(s)}, nil
		}
	}
	host := strings.TrimSuffix(strings.ToLower(s), ".")
	if h, p, err := net.SplitHostPort(host); err == nil {
		if n, err := strconv.Atoi(p); err == nil && n > 0 && n < 65536 && domainRE.MatchString(h) {
			// domain:port is not a ThreatFox type; keep the domain.
			return IOC{Domain, h}, nil
		}
	}
	if domainRE.MatchString(host) {
		return IOC{Domain, host}, nil
	}
	return IOC{}, fmt.Errorf("unrecognised indicator %q", raw)
}

// MustParse is Parse for literals in code and tests.
func MustParse(raw string) IOC {
	i, err := Parse(raw)
	if err != nil {
		panic(err)
	}
	return i
}

// Host returns the host part of a url, ip:port or domain/ip indicator.
func (i IOC) Host() (IOC, bool) {
	switch i.Kind {
	case IP, Domain:
		return i, true
	case IPPort:
		ap, err := netip.ParseAddrPort(i.Value)
		if err != nil {
			return IOC{}, false
		}
		return IOC{IP, ap.Addr().String()}, true
	case URL:
		u, err := url.Parse(i.Value)
		if err != nil {
			return IOC{}, false
		}
		h := u.Hostname()
		if a, err := netip.ParseAddr(h); err == nil {
			return IOC{IP, a.Unmap().String()}, true
		}
		return IOC{Domain, strings.ToLower(h)}, true
	}
	return IOC{}, false
}

// Port returns the TCP port an ip:port or url indicator points at.
func (i IOC) Port() (int, bool) {
	switch i.Kind {
	case IPPort:
		ap, err := netip.ParseAddrPort(i.Value)
		if err != nil {
			return 0, false
		}
		return int(ap.Port()), true
	case URL:
		u, err := url.Parse(i.Value)
		if err != nil {
			return 0, false
		}
		if p := u.Port(); p != "" {
			n, _ := strconv.Atoi(p)
			return n, true
		}
		switch u.Scheme {
		case "http", "ws":
			return 80, true
		case "https", "wss":
			return 443, true
		}
	}
	return 0, false
}

// Path returns the path of a url indicator.
func (i IOC) Path() string {
	if i.Kind != URL {
		return ""
	}
	u, err := url.Parse(i.Value)
	if err != nil {
		return ""
	}
	return u.Path
}

// Routable reports whether an IP indicator is a public unicast address.
// Pivoting off private, loopback or documentation space only produces noise.
func Routable(a netip.Addr) bool {
	if !a.IsValid() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() ||
		a.IsMulticast() || a.IsUnspecified() || a.IsInterfaceLocalMulticast() {
		return false
	}
	for _, p := range nonRoutable {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

var nonRoutable = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// Prefix24 returns the /24 (or /48 for v6) an address sits in.
func Prefix24(a netip.Addr) netip.Prefix {
	bits := 24
	if a.Is6() {
		bits = 48
	}
	p, _ := a.Prefix(bits)
	return p
}

// HasSuffix reports whether domain equals suffix or is a subdomain of it.
func HasSuffix(domain, suffix string) bool {
	domain, suffix = strings.ToLower(domain), strings.ToLower(strings.TrimPrefix(suffix, "."))
	return domain == suffix || strings.HasSuffix(domain, "."+suffix)
}
