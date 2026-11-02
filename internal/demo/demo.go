// Package demo is a synthetic copy of the internet, small enough to read:
// fake ThreatFox, URLhaus and crt.sh answers served by an http.RoundTripper,
// and a fake DNS resolver. `prowl demo` and the tests run a full hunt
// against it with no API key and no network.
//
// Every address is from the RFC 5737 documentation ranges, every domain
// ends in .example (RFC 2606), every AS number is from the RFC 5398
// documentation range except 13335, which stands in for a CDN on purpose.
// None of it describes real infrastructure.
package demo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type tf struct {
	ID         string   `json:"id"`
	IOC        string   `json:"ioc"`
	ThreatType string   `json:"threat_type"`
	IOCType    string   `json:"ioc_type"`
	Malware    string   `json:"malware"`
	Printable  string   `json:"malware_printable"`
	Confidence int      `json:"confidence_level"`
	FirstSeen  string   `json:"first_seen"`
	LastSeen   *string  `json:"last_seen"`
	Reference  string   `json:"reference"`
	Reporter   string   `json:"reporter"`
	Tags       []string `json:"tags"`
}

type uh struct {
	URL       string   `json:"url"`
	Status    string   `json:"url_status"`
	Threat    string   `json:"threat"`
	DateAdded string   `json:"date_added"`
	Tags      []string `json:"tags"`
	Reference string   `json:"urlhaus_reference"`
	Reporter  string   `json:"reporter"`
}

type crt struct {
	ID        int64  `json:"id"`
	Issuer    string `json:"issuer_name"`
	CN        string `json:"common_name"`
	NameValue string `json:"name_value"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	Serial    string `json:"serial_number"`
}

// Data is the synthetic dataset, built relative to now so sighting ages
// (and therefore scores) don't drift as the calendar moves.
type Data struct {
	ThreatFoxMalware map[string][]tf
	ThreatFoxTag     map[string][]tf
	ThreatFoxSearch  map[string][]tf
	URLhaus          map[string][]uh
	Crt              map[string][]crt
	A                map[string][]string
	TXT              map[string][]string
}

// New builds the dataset.
func New(now time.Time) *Data {
	ago := func(days int) string { return now.AddDate(0, 0, -days).Format("2006-01-02 15:04:05") + " UTC" }
	agoPtr := func(days int) *string { s := ago(days); return &s }
	crtTime := func(days int) string { return now.AddDate(0, 0, -days).Format("2006-01-02T15:04:05") }

	oc := func(id, ioc, typ, threat string, conf, first int, last *string, tags ...string) tf {
		return tf{id, ioc, threat, typ, "js.otter_cookie", "OtterCookie", conf, ago(first), last, "", "demo-reporter", tags}
	}
	bt := func(id, ioc string, conf, first int, last *string, tags ...string) tf {
		return tf{id, ioc, "botnet_cc", "ip:port", "js.beavertail", "BeaverTail", conf, ago(first), last, "", "demo-reporter", tags}
	}

	ocC2 := oc("900101", "203.0.113.47:1418", "ip:port", "botnet_cc", 100, 40, agoPtr(3), "OtterCookie", "ContagiousInterview")
	ocC2b := oc("900102", "203.0.113.48:1418", "ip:port", "botnet_cc", 75, 21, nil, "OtterCookie")
	ocDom := oc("900103", "api.nodecheck-cdn.example", "domain", "botnet_cc", 100, 30, nil, "OtterCookie")
	ocURL := oc("900104", "https://assets-loader.vercel.app/api/ipcheck", "url", "payload_delivery", 100, 12, nil, "OtterCookie")
	ocHash := oc("900105", "5c1f0f8f4b2f6d3a9e7c0b1a2d3e4f5061728394a5b6c7d8e9f0a1b2c3d4e5f6", "sha256_hash", "payload", 100, 12, nil, "OtterCookie")
	btC2 := bt("900201", "198.51.100.88:1224", 100, 60, agoPtr(10), "BeaverTail")
	btOld := bt("900202", "198.51.100.89:1244", 50, 300, nil, "BeaverTail")
	btAncient := bt("900203", "198.51.100.90:1244", 100, 500, nil, "BeaverTail")
	bt47 := bt("900204", "203.0.113.47:1224", 75, 25, nil, "BeaverTail")
	lure := tf{"900301", "https://github.com/hr-talent-assess/web3-take-home", "payload_delivery", "url", "unknown", "Unknown malware", 75, ago(15), nil, "", "demo-reporter", []string{"ContagiousInterview", "fake-interview"}}

	d := &Data{
		ThreatFoxMalware: map[string][]tf{
			"js.otter_cookie": {ocC2, ocC2b, ocDom, ocURL, ocHash},
			"js.beavertail":   {btC2, btOld, btAncient},
		},
		ThreatFoxTag: map[string][]tf{
			"OtterCookie":         {ocC2, ocC2b, ocDom, ocURL},
			"BeaverTail":          {btC2},
			"ContagiousInterview": {ocC2, lure},
		},
		ThreatFoxSearch: map[string][]tf{
			"203.0.113.47":              {ocC2, bt47},
			"203.0.113.48":              {ocC2b},
			"198.51.100.88":             {btC2},
			"api.nodecheck-cdn.example": {ocDom},
		},
		URLhaus: map[string][]uh{
			"203.0.113.47": {
				{"http://203.0.113.47:1224/uploads", "online", "malware_download", ago(9), []string{"BeaverTail"}, "https://urlhaus.abuse.ch/url/0000001/", "demo-reporter"},
				{"http://203.0.113.47:1418/socket.io/?EIO=4&transport=polling", "online", "malware_download", ago(5), nil, "https://urlhaus.abuse.ch/url/0000002/", "demo-reporter"},
			},
			"198.51.100.88": {
				{"http://198.51.100.88:1224/pdown", "offline", "malware_download", ago(30), []string{"BeaverTail", "InvisibleFerret"}, "https://urlhaus.abuse.ch/url/0000003/", "demo-reporter"},
				{"http://198.51.100.88:1224/keys", "offline", "malware_download", ago(30), nil, "https://urlhaus.abuse.ch/url/0000004/", "demo-reporter"},
			},
		},
		Crt: map[string][]crt{
			"api.nodecheck-cdn.example": {
				{7000001, "C=US, O=Let's Encrypt, CN=R11", "nodecheck-cdn.example", "nodecheck-cdn.example\napi.nodecheck-cdn.example\ncdn.nodecheck-cdn.example", crtTime(33), crtTime(-57), "04a1b2"},
				{7000002, "C=US, O=Let's Encrypt, CN=R11", "api.nodecheck-cdn.example", "api.nodecheck-cdn.example\nmetrics.devhire-portal.example", crtTime(31), crtTime(-59), "04c3d4"},
			},
			"nodecheck-cdn.example": {
				{7000001, "C=US, O=Let's Encrypt, CN=R11", "nodecheck-cdn.example", "nodecheck-cdn.example\napi.nodecheck-cdn.example\ncdn.nodecheck-cdn.example", crtTime(33), crtTime(-57), "04a1b2"},
			},
			"metrics.devhire-portal.example": {
				{7000002, "C=US, O=Let's Encrypt, CN=R11", "api.nodecheck-cdn.example", "api.nodecheck-cdn.example\nmetrics.devhire-portal.example", crtTime(31), crtTime(-59), "04c3d4"},
				{7000003, "C=US, O=Example SaaS CA, CN=Example SaaS CA", "*.saas-panel.example", saasNames(60), crtTime(90), crtTime(-275), "0999"},
			},
		},
		A: map[string][]string{
			"api.nodecheck-cdn.example":      {"203.0.113.49"},
			"nodecheck-cdn.example":          {"203.0.113.49"},
			"cdn.nodecheck-cdn.example":      {"192.0.2.80"},
			"metrics.devhire-portal.example": {"192.0.2.15"},
		},
		TXT: map[string][]string{},
	}

	asn := map[string][2]string{
		"203.0.113.47":  {"64500 | 203.0.113.0/24 | NL | ripencc | 2021-05-11", "64500"},
		"203.0.113.48":  {"64500 | 203.0.113.0/24 | NL | ripencc | 2021-05-11", "64500"},
		"203.0.113.49":  {"64500 | 203.0.113.0/24 | NL | ripencc | 2021-05-11", "64500"},
		"198.51.100.88": {"64501 | 198.51.100.0/24 | US | arin | 2019-02-01", "64501"},
		"198.51.100.89": {"64501 | 198.51.100.0/24 | US | arin | 2019-02-01", "64501"},
		"192.0.2.80":    {"13335 | 192.0.2.0/24 | US | arin | 2010-07-14", "13335"},
		"192.0.2.15":    {"64510 | 192.0.2.0/24 | DE | ripencc | 2020-01-01", "64510"},
	}
	names := map[string]string{
		"64500": "64500 | NL | ripencc | 2021-05-11 | EXAMPLE-VPS-AS Example VPS B.V., NL",
		"64501": "64501 | US | arin | 2019-02-01 | EXAMPLE-HOSTING-AS, US",
		"13335": "13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US",
		"64510": "64510 | DE | ripencc | 2020-01-01 | EXAMPLE-DE-AS, DE",
	}
	for ip, a := range asn {
		p := strings.Split(ip, ".")
		d.TXT[fmt.Sprintf("%s.%s.%s.%s.origin.asn.cymru.com", p[3], p[2], p[1], p[0])] = []string{a[0]}
		d.TXT["AS"+a[1]+".asn.cymru.com"] = []string{names[a[1]]}
	}
	return d
}

func saasNames(n int) string {
	var b []string
	for i := 0; i < n; i++ {
		b = append(b, fmt.Sprintf("tenant%02d.saas-panel.example", i))
	}
	return strings.Join(b, "\n")
}

// Transport answers requests to the real API hostnames from the dataset.
func (d *Data) Transport() http.RoundTripper { return rt{d} }

type rt struct{ d *Data }

func (t rt) RoundTrip(r *http.Request) (*http.Response, error) {
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
	}
	switch r.URL.Hostname() {
	case "threatfox-api.abuse.ch":
		var q map[string]any
		_ = json.Unmarshal(body, &q)
		s := func(k string) string { v, _ := q[k].(string); return v }
		var recs []tf
		switch s("query") {
		case "malwareinfo":
			recs = t.d.ThreatFoxMalware[s("malware")]
		case "taginfo":
			recs = t.d.ThreatFoxTag[s("tag")]
		case "search_ioc":
			recs = t.d.ThreatFoxSearch[s("search_term")]
		default:
			return reply(r, 200, map[string]any{"query_status": "unknown_query"})
		}
		if len(recs) == 0 {
			return reply(r, 200, map[string]any{"query_status": "no_result", "data": "Your search did not yield any results"})
		}
		return reply(r, 200, map[string]any{"query_status": "ok", "data": recs})
	case "urlhaus-api.abuse.ch":
		form, _ := url.ParseQuery(string(body))
		urls := t.d.URLhaus[form.Get("host")]
		if len(urls) == 0 {
			return reply(r, 200, map[string]any{"query_status": "no_results"})
		}
		return reply(r, 200, map[string]any{"query_status": "ok", "host": form.Get("host"), "url_count": fmt.Sprint(len(urls)), "urls": urls})
	case "crt.sh":
		rows := t.d.Crt[r.URL.Query().Get("q")]
		if rows == nil {
			rows = []crt{}
		}
		return reply(r, 200, rows)
	}
	return nil, fmt.Errorf("demo: no route to %s (the demo never leaves the process)", r.URL.Host)
}

func reply(r *http.Request, status int, v any) (*http.Response, error) {
	b, _ := json.Marshal(v)
	return &http.Response{
		StatusCode: status, Status: http.StatusText(status), Request: r,
		Header: http.Header{"Content-Type": {"application/json"}},
		Body:   io.NopCloser(bytes.NewReader(b)), ContentLength: int64(len(b)),
	}, nil
}

// Resolver answers DNS from the dataset.
func (d *Data) Resolver() Resolver { return Resolver{d} }

// Resolver implements source.Resolver.
type Resolver struct{ d *Data }

func notFound(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (r Resolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if a, ok := r.d.A[host]; ok {
		return a, nil
	}
	return nil, notFound(host)
}

func (r Resolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if t, ok := r.d.TXT[name]; ok {
		return t, nil
	}
	return nil, notFound(name)
}

func (r Resolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	return nil, notFound(addr)
}
