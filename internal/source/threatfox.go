package source

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ThreatFox queries the abuse.ch ThreatFox API. An Auth-Key is required
// (free, from https://auth.abuse.ch/); it is shared with URLhaus.
type ThreatFox struct {
	C    *Client
	Key  string
	Base string // default https://threatfox-api.abuse.ch/api/v1/
}

// TFIOC is one ThreatFox record.
type TFIOC struct {
	ID         string    `json:"id"`
	IOC        string    `json:"ioc"`
	ThreatType string    `json:"threat_type"`
	IOCType    string    `json:"ioc_type"`
	Malware    string    `json:"malware"`
	Printable  string    `json:"malware_printable"`
	Confidence int       `json:"confidence_level"`
	FirstSeen  time.Time `json:"-"`
	LastSeen   time.Time `json:"-"`
	Reference  string    `json:"reference"`
	Reporter   string    `json:"reporter"`
	Tags       []string  `json:"tags"`

	RawFirst string  `json:"first_seen"`
	RawLast  *string `json:"last_seen"`
}

// Seen is the most recent time this IOC was reported active.
func (t TFIOC) Seen() time.Time {
	if !t.LastSeen.IsZero() {
		return t.LastSeen
	}
	return t.FirstSeen
}

const abuseTime = "2006-01-02 15:04:05 MST"

func parseAbuseTime(s string) time.Time {
	t, err := time.Parse(abuseTime, strings.TrimSpace(s))
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

func (t *ThreatFox) base() string {
	if t.Base != "" {
		return t.Base
	}
	return "https://threatfox-api.abuse.ch/api/v1/"
}

func (t *ThreatFox) query(ctx context.Context, q map[string]any) ([]TFIOC, error) {
	if t.Key == "" && !t.C.Offline {
		return nil, fmt.Errorf("threatfox: no Auth-Key (set ABUSECH_AUTH_KEY)")
	}
	body, _ := json.Marshal(q)
	raw, _, err := t.C.Do(ctx, Request{
		Method:  http.MethodPost,
		URL:     t.base(),
		Body:    body,
		Header:  http.Header{"Content-Type": {"application/json"}},
		Secrets: http.Header{"Auth-Key": {t.Key}},
	})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Status string          `json:"query_status"`
		Data   json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("threatfox: %w", err)
	}
	switch resp.Status {
	case "ok":
	case "no_result", "no_results":
		return nil, nil
	default:
		return nil, fmt.Errorf("threatfox: query_status %q", resp.Status)
	}
	// On no_result "data" is a sentence, not an array.
	if len(resp.Data) == 0 || resp.Data[0] != '[' {
		return nil, nil
	}
	var out []TFIOC
	if err := json.Unmarshal(resp.Data, &out); err != nil {
		return nil, fmt.Errorf("threatfox: %w", err)
	}
	for i := range out {
		out[i].FirstSeen = parseAbuseTime(out[i].RawFirst)
		if out[i].RawLast != nil {
			out[i].LastSeen = parseAbuseTime(*out[i].RawLast)
		}
	}
	return out, nil
}

// Malware returns IOCs filed under a malware family (e.g. js.otter_cookie).
func (t *ThreatFox) Malware(ctx context.Context, name string, limit int) ([]TFIOC, error) {
	return t.query(ctx, map[string]any{"query": "malwareinfo", "malware": name, "limit": limit})
}

// Tag returns IOCs carrying a tag.
func (t *ThreatFox) Tag(ctx context.Context, tag string, limit int) ([]TFIOC, error) {
	return t.query(ctx, map[string]any{"query": "taginfo", "tag": tag, "limit": limit})
}

// Search looks up an exact IOC value (ip, domain, url, ip:port).
func (t *ThreatFox) Search(ctx context.Context, term string) ([]TFIOC, error) {
	return t.query(ctx, map[string]any{"query": "search_ioc", "search_term": term, "exact_match": true})
}
