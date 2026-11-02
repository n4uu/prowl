package source

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// CrtSh queries certificate transparency through crt.sh.
type CrtSh struct {
	C    *Client
	Base string // default https://crt.sh/
}

// Cert is one certificate (deduplicated across precert/leaf log entries).
type Cert struct {
	ID        int64     `json:"id"`
	Issuer    string    `json:"issuer"`
	Names     []string  `json:"names"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	Serial    string    `json:"serial"`
}

type crtRow struct {
	ID         int64  `json:"id"`
	IssuerName string `json:"issuer_name"`
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
	Serial     string `json:"serial_number"`
}

func (c *CrtSh) base() string {
	if c.Base != "" {
		return c.Base
	}
	return "https://crt.sh/"
}

// Certs returns certificates whose names include domain. crt.sh lists the
// precertificate and the final certificate separately; they share a serial
// and are merged here so SAN counts aren't doubled.
func (c *CrtSh) Certs(ctx context.Context, domain string) ([]Cert, error) {
	q := url.Values{"q": {domain}, "output": {"json"}}
	raw, _, err := c.C.Do(ctx, Request{Method: http.MethodGet, URL: c.base() + "?" + q.Encode()})
	if err != nil {
		return nil, err
	}
	raw = []byte(strings.TrimSpace(string(raw)))
	if len(raw) == 0 || raw[0] != '[' {
		return nil, fmt.Errorf("crt.sh: unexpected response")
	}
	var rows []crtRow
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("crt.sh: %w", err)
	}
	bySerial := map[string]*Cert{}
	var order []string
	for _, r := range rows {
		k := r.Serial
		if k == "" {
			k = fmt.Sprint(r.ID)
		}
		cert := bySerial[k]
		if cert == nil {
			cert = &Cert{ID: r.ID, Issuer: issuerCN(r.IssuerName), Serial: r.Serial,
				NotBefore: parseCrtTime(r.NotBefore), NotAfter: parseCrtTime(r.NotAfter)}
			bySerial[k] = cert
			order = append(order, k)
		}
		for _, n := range append(strings.Split(r.NameValue, "\n"), r.CommonName) {
			n = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(n), "*."))
			if n != "" && !contains(cert.Names, n) {
				cert.Names = append(cert.Names, n)
			}
		}
	}
	out := make([]Cert, 0, len(order))
	for _, k := range order {
		sort.Strings(bySerial[k].Names)
		out = append(out, *bySerial[k])
	}
	return out, nil
}

func parseCrtTime(s string) time.Time {
	for _, layout := range []string{"2006-01-02T15:04:05", "2006-01-02T15:04:05.999"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func issuerCN(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CN=") {
			return strings.TrimPrefix(part, "CN=")
		}
	}
	return dn
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
