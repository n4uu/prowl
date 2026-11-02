package source

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// URLhaus queries the abuse.ch URLhaus API (same Auth-Key as ThreatFox).
type URLhaus struct {
	C    *Client
	Key  string
	Base string // default https://urlhaus-api.abuse.ch/v1/
}

// UHURL is one URL URLhaus has on record for a host.
type UHURL struct {
	URL       string    `json:"url"`
	Status    string    `json:"url_status"`
	Threat    string    `json:"threat"`
	RawAdded  string    `json:"date_added"`
	Added     time.Time `json:"-"`
	Tags      []string  `json:"tags"`
	Reference string    `json:"urlhaus_reference"`
	Reporter  string    `json:"reporter"`
}

func (u *URLhaus) base() string {
	if u.Base != "" {
		return u.Base
	}
	return "https://urlhaus-api.abuse.ch/v1/"
}

// Host returns the URLs URLhaus knows on a host (domain or IP).
func (u *URLhaus) Host(ctx context.Context, host string) ([]UHURL, error) {
	if u.Key == "" && !u.C.Offline {
		return nil, fmt.Errorf("urlhaus: no Auth-Key (set ABUSECH_AUTH_KEY)")
	}
	form := url.Values{"host": {host}}.Encode()
	raw, _, err := u.C.Do(ctx, Request{
		Method:  http.MethodPost,
		URL:     u.base() + "host/",
		Body:    []byte(form),
		Header:  http.Header{"Content-Type": {"application/x-www-form-urlencoded"}},
		Secrets: http.Header{"Auth-Key": {u.Key}},
	})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Status string  `json:"query_status"`
		URLs   []UHURL `json:"urls"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("urlhaus: %w", err)
	}
	switch resp.Status {
	case "ok":
	case "no_results", "no_result":
		return nil, nil
	default:
		return nil, fmt.Errorf("urlhaus: query_status %q", resp.Status)
	}
	for i := range resp.URLs {
		resp.URLs[i].Added = parseAbuseTime(resp.URLs[i].RawAdded)
	}
	return resp.URLs, nil
}
