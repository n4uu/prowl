package source

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Resolver is the subset of net.Resolver prowl uses.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// DNS answers A/AAAA, PTR and Team Cymru ASN lookups, through the same
// cache as the HTTP sources. Answers change, so the cache records when they
// were taken; a hunt replayed next year shows what resolved at the time.
type DNS struct {
	R       Resolver
	Cache   Cache
	Offline bool
}

// NewDNS uses the system resolver.
func NewDNS(cache Cache, offline bool) *DNS {
	return &DNS{R: net.DefaultResolver, Cache: cache, Offline: offline}
}

func (d *DNS) cached(ctx context.Context, q string, fn func() ([]string, error)) ([]string, error) {
	key := Key("dns " + q)
	if d.Cache != nil {
		if rec, ok := d.Cache.Get(key); ok {
			var out []string
			_ = json.Unmarshal([]byte(rec.Body), &out)
			return out, nil
		}
	}
	if d.Offline {
		return nil, ErrNotCached
	}
	ans, err := fn()
	if err != nil {
		var de *net.DNSError
		if errors.As(err, &de) && de.IsNotFound {
			ans, err = nil, nil // NXDOMAIN is an answer, cache it
		} else {
			return nil, err
		}
	}
	sort.Strings(ans)
	if d.Cache != nil {
		b, _ := json.Marshal(ans)
		_ = d.Cache.Put(key, Record{Request: "dns " + q, Status: 0, Fetched: time.Now().UTC(), Body: string(b)})
	}
	return ans, nil
}

// Addrs resolves a host name.
func (d *DNS) Addrs(ctx context.Context, host string) ([]netip.Addr, error) {
	ans, err := d.cached(ctx, "A "+host, func() ([]string, error) { return d.R.LookupHost(ctx, host) })
	var out []netip.Addr
	for _, a := range ans {
		if ip, err := netip.ParseAddr(a); err == nil {
			out = append(out, ip.Unmap())
		}
	}
	return out, err
}

// PTR returns reverse names for an address.
func (d *DNS) PTR(ctx context.Context, ip netip.Addr) ([]string, error) {
	ans, err := d.cached(ctx, "PTR "+ip.String(), func() ([]string, error) { return d.R.LookupAddr(ctx, ip.String()) })
	for i := range ans {
		ans[i] = strings.TrimSuffix(strings.ToLower(ans[i]), ".")
	}
	return ans, err
}

// ASN is Team Cymru's view of who announces an address.
type ASN struct {
	Number   string `json:"asn"`
	Prefix   string `json:"prefix"`
	Country  string `json:"country"`
	Registry string `json:"registry"`
	Name     string `json:"as_name"`
}

// ASN looks an address up in Team Cymru's DNS interface:
// <reversed ip>.origin.asn.cymru.com TXT "13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11"
// AS13335.asn.cymru.com TXT "13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US"
func (d *DNS) ASN(ctx context.Context, ip netip.Addr) (ASN, error) {
	var q string
	if ip.Is4() {
		b := ip.As4()
		q = fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", b[3], b[2], b[1], b[0])
	} else {
		b := ip.As16()
		var nib []string
		for i := 15; i >= 0; i-- {
			nib = append(nib, fmt.Sprintf("%x.%x", b[i]&0x0f, b[i]>>4))
		}
		q = strings.Join(nib, ".") + ".origin6.asn.cymru.com"
	}
	txt, err := d.cached(ctx, "TXT "+q, func() ([]string, error) { return d.R.LookupTXT(ctx, q) })
	if err != nil || len(txt) == 0 {
		return ASN{}, err
	}
	f := splitPipes(txt[0])
	if len(f) < 4 {
		return ASN{}, fmt.Errorf("cymru: odd answer %q", txt[0])
	}
	a := ASN{Number: strings.Fields(f[0])[0], Prefix: f[1], Country: f[2], Registry: f[3]}
	name := "AS" + a.Number + ".asn.cymru.com"
	if txt, err := d.cached(ctx, "TXT "+name, func() ([]string, error) { return d.R.LookupTXT(ctx, name) }); err == nil && len(txt) > 0 {
		if g := splitPipes(txt[0]); len(g) >= 5 {
			a.Name = g[4]
		}
	}
	return a, nil
}

func splitPipes(s string) []string {
	parts := strings.Split(s, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}
