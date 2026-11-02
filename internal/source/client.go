// Package source talks to the public telemetry prowl pivots through:
// ThreatFox, URLhaus, crt.sh, DNS and Team Cymru's IP-to-ASN service.
//
// Every response goes through a cache keyed by the request (minus any auth
// header). Run once online with -cache, and the same hunt replays offline
// from that directory forever after: reproducible results for a report, and
// no hammering of free services while tuning a profile.
package source

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ErrNotCached is returned in offline mode when a request isn't in the cache.
var ErrNotCached = errors.New("not in cache (offline)")

// Record is one cached response.
type Record struct {
	Request string    `json:"request"`
	Status  int       `json:"status"`
	Fetched time.Time `json:"fetched"`
	Body    string    `json:"body"`
}

// Cache stores responses by request key.
type Cache interface {
	Get(key string) (Record, bool)
	Put(key string, r Record) error
}

// DirCache keeps one JSON file per request. Entries older than TTL are
// treated as missing (TTL 0 keeps them forever).
type DirCache struct {
	Dir string
	TTL time.Duration
}

func (d *DirCache) path(key string) string {
	return filepath.Join(d.Dir, key[:2], key+".json")
}

func (d *DirCache) Get(key string) (Record, bool) {
	b, err := os.ReadFile(d.path(key))
	if err != nil {
		return Record{}, false
	}
	var r Record
	if json.Unmarshal(b, &r) != nil {
		return Record{}, false
	}
	if d.TTL > 0 && time.Since(r.Fetched) > d.TTL {
		return Record{}, false
	}
	return r, true
}

func (d *DirCache) Put(key string, r Record) error {
	p := d.path(key)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// MemCache is an in-memory cache, used by the demo dataset and tests.
type MemCache struct {
	mu sync.Mutex
	m  map[string]Record
}

func NewMemCache() *MemCache { return &MemCache{m: map[string]Record{}} }

func (m *MemCache) Get(key string) (Record, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.m[key]
	return r, ok
}

func (m *MemCache) Put(key string, r Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.m[key] = r
	return nil
}

// Key derives the cache key for a request description.
func Key(request string) string {
	sum := sha256.Sum256([]byte(request))
	return hex.EncodeToString(sum[:])[:32]
}

// Stats counts what each upstream was asked.
type Stats struct {
	Requests  int `json:"requests"`
	CacheHits int `json:"cache_hits"`
	Misses    int `json:"offline_misses"`
	Errors    int `json:"errors"`
}

// Client is a polite HTTP client: cache first, per-host spacing between
// requests, retries with backoff on 429/5xx.
type Client struct {
	HTTP      *http.Client
	Cache     Cache
	Offline   bool
	UserAgent string
	// MinInterval is the minimum gap between two live requests to the same
	// host. crt.sh in particular rate-limits aggressively.
	MinInterval map[string]time.Duration
	Retries     int

	mu    sync.Mutex
	last  map[string]time.Time
	stats map[string]*Stats
}

// NewClient returns a client with sane defaults.
func NewClient(cache Cache, offline bool) *Client {
	return &Client{
		HTTP:      &http.Client{Timeout: 45 * time.Second},
		Cache:     cache,
		Offline:   offline,
		UserAgent: "prowl (+https://github.com/n4uu/prowl)",
		MinInterval: map[string]time.Duration{
			"crt.sh":                 3 * time.Second,
			"threatfox-api.abuse.ch": 500 * time.Millisecond,
			"urlhaus-api.abuse.ch":   500 * time.Millisecond,
		},
		Retries: 3,
	}
}

// Stats returns a copy of the per-host counters.
func (c *Client) Stats() map[string]Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]Stats{}
	for k, v := range c.stats {
		out[k] = *v
	}
	return out
}

func (c *Client) stat(host string) *Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stats == nil {
		c.stats = map[string]*Stats{}
	}
	s := c.stats[host]
	if s == nil {
		s = &Stats{}
		c.stats[host] = s
	}
	return s
}

// Request is one upstream call. Secret headers are sent but never become
// part of the cache key or the cached record.
type Request struct {
	Method  string
	URL     string
	Body    []byte
	Header  http.Header
	Secrets http.Header
}

func (r Request) describe() string {
	return r.Method + " " + r.URL + "\n" + string(r.Body)
}

// Do performs a request through the cache.
func (c *Client) Do(ctx context.Context, req Request) ([]byte, int, error) {
	u, err := url.Parse(req.URL)
	if err != nil {
		return nil, 0, err
	}
	host := u.Hostname()
	st := c.stat(host)
	key := Key(req.describe())

	if c.Cache != nil {
		if rec, ok := c.Cache.Get(key); ok {
			c.mu.Lock()
			st.CacheHits++
			c.mu.Unlock()
			return []byte(rec.Body), rec.Status, nil
		}
	}
	if c.Offline {
		c.mu.Lock()
		st.Misses++
		c.mu.Unlock()
		return nil, 0, ErrNotCached
	}

	var body []byte
	var status int
	backoff := 2 * time.Second
	for attempt := 0; ; attempt++ {
		if err := c.wait(ctx, host); err != nil {
			return nil, 0, err
		}
		c.mu.Lock()
		st.Requests++
		c.mu.Unlock()
		body, status, err = c.once(ctx, req)
		retryable := err != nil || status == 429 || status >= 500
		if !retryable || attempt >= c.Retries {
			break
		}
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
	}
	if err != nil {
		c.mu.Lock()
		st.Errors++
		c.mu.Unlock()
		return nil, status, err
	}
	if status >= 400 {
		c.mu.Lock()
		st.Errors++
		c.mu.Unlock()
		return body, status, fmt.Errorf("%s: HTTP %d", host, status)
	}
	if c.Cache != nil {
		_ = c.Cache.Put(key, Record{Request: req.describe(), Status: status, Fetched: time.Now().UTC(), Body: string(body)})
	}
	return body, status, nil
}

func (c *Client) once(ctx context.Context, req Request) ([]byte, int, error) {
	var rd io.Reader
	if req.Body != nil {
		rd = bytes.NewReader(req.Body)
	}
	hr, err := http.NewRequestWithContext(ctx, req.Method, req.URL, rd)
	if err != nil {
		return nil, 0, err
	}
	hr.Header.Set("User-Agent", c.UserAgent)
	for k, vs := range req.Header {
		for _, v := range vs {
			hr.Header.Add(k, v)
		}
	}
	for k, vs := range req.Secrets {
		for _, v := range vs {
			hr.Header.Add(k, v)
		}
	}
	resp, err := c.HTTP.Do(hr)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	return b, resp.StatusCode, err
}

func (c *Client) wait(ctx context.Context, host string) error {
	gap := c.MinInterval[host]
	if gap == 0 {
		return nil
	}
	c.mu.Lock()
	if c.last == nil {
		c.last = map[string]time.Time{}
	}
	next := c.last[host].Add(gap)
	now := time.Now()
	if next.Before(now) {
		next = now
	}
	c.last[host] = next
	c.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(time.Until(next)):
		return nil
	}
}
