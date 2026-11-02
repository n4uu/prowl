package source

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestThreatFoxParsing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Auth-Key") != "k" {
			w.WriteHeader(401)
			return
		}
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), "nothing") {
			io.WriteString(w, `{"query_status":"no_result","data":"Your search did not yield any results"}`)
			return
		}
		io.WriteString(w, `{"query_status":"ok","data":[{"id":"1","ioc":"203.0.113.47:1418","threat_type":"botnet_cc","ioc_type":"ip:port","malware":"js.otter_cookie","malware_printable":"OtterCookie","confidence_level":100,"first_seen":"2026-09-01 10:00:00 UTC","last_seen":null,"reporter":"r","tags":["OtterCookie"]},{"id":"2","ioc":"x.example","ioc_type":"domain","malware":"js.otter_cookie","first_seen":"2026-09-01 10:00:00 UTC","last_seen":"2026-10-01 11:00:00 UTC","tags":null}]}`)
	}))
	defer srv.Close()

	tf := &ThreatFox{C: NewClient(nil, false), Key: "k", Base: srv.URL + "/"}
	recs, err := tf.Malware(context.Background(), "js.otter_cookie", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || recs[0].IOC != "203.0.113.47:1418" || recs[0].Confidence != 100 {
		t.Fatalf("recs = %+v", recs)
	}
	if recs[0].Seen() != time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC) {
		t.Errorf("first-seen fallback: %v", recs[0].Seen())
	}
	if recs[1].Seen() != time.Date(2026, 10, 1, 11, 0, 0, 0, time.UTC) {
		t.Errorf("last_seen: %v", recs[1].Seen())
	}
	none, err := tf.Search(context.Background(), "nothing")
	if err != nil || none != nil {
		t.Errorf("no_result: %v %v", none, err)
	}
}

func TestCacheNeverStoresTheKeyAndReplaysOffline(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		io.WriteString(w, `{"query_status":"ok","urls":[{"url":"http://198.51.100.88:1224/pdown","url_status":"online","threat":"malware_download","date_added":"2026-10-01 00:00:00 UTC","tags":["BeaverTail"]}]}`)
	}))
	defer srv.Close()
	dir := t.TempDir()
	cache := &DirCache{Dir: dir}

	online := &URLhaus{C: NewClient(cache, false), Key: "super-secret-key", Base: srv.URL + "/"}
	if _, err := online.Host(context.Background(), "198.51.100.88"); err != nil {
		t.Fatal(err)
	}
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if info != nil && !info.IsDir() {
			b, _ := os.ReadFile(p)
			if strings.Contains(string(b), "super-secret-key") {
				t.Errorf("auth key written to cache file %s", p)
			}
		}
		return nil
	})

	offline := &URLhaus{C: NewClient(cache, true), Base: srv.URL + "/"}
	urls, err := offline.Host(context.Background(), "198.51.100.88")
	if err != nil || len(urls) != 1 || urls[0].Tags[0] != "BeaverTail" {
		t.Fatalf("offline replay: %+v %v", urls, err)
	}
	if _, err := offline.Host(context.Background(), "203.0.113.1"); err != ErrNotCached {
		t.Errorf("uncached offline lookup: %v", err)
	}
	if hits != 1 {
		t.Errorf("server hit %d times, want 1", hits)
	}
}

func TestRetryOn503(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) == 1 {
			w.WriteHeader(503)
			return
		}
		io.WriteString(w, `[]`)
	}))
	defer srv.Close()
	c := NewClient(nil, false)
	c.Retries = 2
	start := time.Now()
	crt := &CrtSh{C: c, Base: srv.URL + "/"}
	if _, err := crt.Certs(context.Background(), "x.example"); err != nil {
		t.Fatal(err)
	}
	if n != 2 || time.Since(start) < time.Second {
		t.Errorf("requests=%d elapsed=%v: no backoff/retry", n, time.Since(start))
	}
}

func TestCrtShMergesPrecertAndLeaf(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("q") != "api.c2.example" || r.URL.Query().Get("output") != "json" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `[
		 {"id":11,"issuer_name":"C=US, O=Let's Encrypt, CN=R11","common_name":"api.c2.example","name_value":"api.c2.example\n*.c2.example","not_before":"2026-09-01T00:00:00","not_after":"2026-11-30T00:00:00","serial_number":"0abc"},
		 {"id":12,"issuer_name":"C=US, O=Let's Encrypt, CN=R11","common_name":"api.c2.example","name_value":"api.c2.example\n*.c2.example","not_before":"2026-09-01T00:00:00","not_after":"2026-11-30T00:00:00","serial_number":"0abc"},
		 {"id":13,"issuer_name":"C=US, O=Let's Encrypt, CN=E6","common_name":"api.c2.example","name_value":"api.c2.example\nother.example","not_before":"2026-10-01T00:00:00","not_after":"2026-12-30T00:00:00","serial_number":"0def"}]`)
	}))
	defer srv.Close()
	certs, err := (&CrtSh{C: NewClient(nil, false), Base: srv.URL + "/"}).Certs(context.Background(), "api.c2.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 {
		t.Fatalf("got %d certs, want 2 (precert+leaf merged)", len(certs))
	}
	if strings.Join(certs[0].Names, ",") != "api.c2.example,c2.example" || certs[0].Issuer != "R11" {
		t.Errorf("cert 0 = %+v", certs[0])
	}
}

type fakeResolver map[string][]string

func (f fakeResolver) LookupHost(_ context.Context, h string) ([]string, error) {
	return f["A "+h], nil
}
func (f fakeResolver) LookupTXT(_ context.Context, n string) ([]string, error) {
	return f["TXT "+n], nil
}
func (f fakeResolver) LookupAddr(_ context.Context, a string) ([]string, error) {
	return f["PTR "+a], nil
}

func TestCymru(t *testing.T) {
	d := &DNS{R: fakeResolver{
		"TXT 47.113.0.203.origin.asn.cymru.com": {"64500 | 203.0.113.0/24 | NL | ripencc | 2021-05-11"},
		"TXT AS64500.asn.cymru.com":             {"64500 | NL | ripencc | 2021-05-11 | EXAMPLE-VPS-AS Example VPS B.V., NL"},
		"TXT 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.origin6.asn.cymru.com": {"64501 | 2001:db8::/32 | US | arin | 2019-01-01"},
	}}
	a, err := d.ASN(context.Background(), netip.MustParseAddr("203.0.113.47"))
	if err != nil || a.Number != "64500" || a.Prefix != "203.0.113.0/24" || a.Name != "EXAMPLE-VPS-AS Example VPS B.V., NL" {
		t.Errorf("v4: %+v %v", a, err)
	}
	a, err = d.ASN(context.Background(), netip.MustParseAddr("2001:db8::1"))
	if err != nil || a.Number != "64501" {
		t.Errorf("v6: %+v %v", a, err)
	}
}
