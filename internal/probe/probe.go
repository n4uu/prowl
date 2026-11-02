// Package probe actively checks whether an address is running an
// Engine.IO / Socket.IO server, the transport OtterCookie's shell uses.
//
// This touches the suspected C2 from your address. It's off unless asked
// for, and should go out through infrastructure you don't mind the operator
// seeing (a VPN you've verified, e.g. with wireguardian).
package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Result describes an Engine.IO handshake answer.
type Result struct {
	Target       string   `json:"target"`
	Live         bool     `json:"live"`
	EIO          int      `json:"eio,omitempty"`
	SID          string   `json:"sid,omitempty"`
	Upgrades     []string `json:"upgrades,omitempty"`
	PingInterval int      `json:"ping_interval_ms,omitempty"`
	PingTimeout  int      `json:"ping_timeout_ms,omitempty"`
	Server       string   `json:"server_header,omitempty"`
	PoweredBy    string   `json:"x_powered_by,omitempty"`
	Status       int      `json:"status,omitempty"`
	Error        string   `json:"error,omitempty"`
}

// Prober sends the handshake.
type Prober struct {
	HTTP *http.Client
	// UserAgent mimics socket.io-client running under Node, which sends no
	// browser UA; servers that filter on it see what they expect.
	UserAgent string
}

// New returns a prober with a short timeout.
func New() *Prober {
	return &Prober{
		HTTP: &http.Client{
			Timeout: 8 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		UserAgent: "node",
	}
}

var v3Prefix = regexp.MustCompile(`^\d+:`)

// Check asks host:port for an Engine.IO v4 handshake, falling back to v3.
func (p *Prober) Check(ctx context.Context, hostport string) Result {
	r := Result{Target: hostport}
	for _, eio := range []int{4, 3} {
		u := fmt.Sprintf("http://%s/socket.io/?EIO=%d&transport=polling&t=%s", hostport, eio, cacheBuster())
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			r.Error = err.Error()
			return r
		}
		req.Header.Set("User-Agent", p.UserAgent)
		req.Header.Set("Accept", "*/*")
		resp, err := p.HTTP.Do(req)
		if err != nil {
			r.Error = err.Error()
			return r
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		r.Status = resp.StatusCode
		r.Server = resp.Header.Get("Server")
		r.PoweredBy = resp.Header.Get("X-Powered-By")

		s := string(body)
		if eio == 3 {
			s = v3Prefix.ReplaceAllString(s, "")
		}
		if resp.StatusCode == 200 && strings.HasPrefix(s, "0{") {
			var open struct {
				SID          string   `json:"sid"`
				Upgrades     []string `json:"upgrades"`
				PingInterval int      `json:"pingInterval"`
				PingTimeout  int      `json:"pingTimeout"`
			}
			end := strings.IndexByte(s, '}')
			if end > 0 && json.Unmarshal([]byte(s[1:end+1]), &open) == nil && open.SID != "" {
				r.Live, r.EIO, r.SID = true, eio, open.SID
				r.Upgrades, r.PingInterval, r.PingTimeout = open.Upgrades, open.PingInterval, open.PingTimeout
				return r
			}
		}
		// A v4 server answers a v3 client with 400 {"code":5,"message":"Unsupported protocol version"},
		// and the reverse; only retry when that's what happened.
		if !strings.Contains(s, "Unsupported protocol version") && resp.StatusCode != 400 {
			break
		}
	}
	return r
}

// engine.io-client's yeast() timestamps look like this; a fixed string would
// be its own fingerprint.
func cacheBuster() string {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_"
	n := time.Now().UnixMilli()
	var b []byte
	for n > 0 {
		b = append([]byte{alphabet[n%64]}, b...)
		n /= 64
	}
	return string(b) + "." + strconv.Itoa(rand.Intn(10))
}
