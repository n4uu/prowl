package probe

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func host(s *httptest.Server) string { return strings.TrimPrefix(s.URL, "http://") }

func TestEngineIOv4(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/socket.io/" || r.URL.Query().Get("EIO") != "4" || r.URL.Query().Get("transport") != "polling" {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("X-Powered-By", "Express")
		io.WriteString(w, `0{"sid":"abc123","upgrades":["websocket"],"pingInterval":25000,"pingTimeout":20000,"maxPayload":1000000}`)
	}))
	defer srv.Close()
	r := New().Check(context.Background(), host(srv))
	if !r.Live || r.EIO != 4 || r.SID != "abc123" || r.PingInterval != 25000 || r.PoweredBy != "Express" {
		t.Errorf("%+v", r)
	}
}

func TestEngineIOv3Fallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("EIO") != "3" {
			w.WriteHeader(400)
			io.WriteString(w, `{"code":5,"message":"Unsupported protocol version"}`)
			return
		}
		io.WriteString(w, `96:0{"sid":"v3sid","upgrades":["websocket"],"pingInterval":25000,"pingTimeout":5000}2:40`)
	}))
	defer srv.Close()
	r := New().Check(context.Background(), host(srv))
	if !r.Live || r.EIO != 3 || r.SID != "v3sid" {
		t.Errorf("%+v", r)
	}
}

func TestNotEngineIO(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "<html>it works</html>")
	}))
	defer srv.Close()
	if r := New().Check(context.Background(), host(srv)); r.Live || r.Status != 200 {
		t.Errorf("%+v", r)
	}
}
