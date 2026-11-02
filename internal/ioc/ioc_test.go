package ioc

import (
	"net/netip"
	"testing"
)

func TestParse(t *testing.T) {
	cases := []struct {
		in   string
		kind Kind
		val  string
	}{
		{"203.0.113.47", IP, "203.0.113.47"},
		{"203.0.113[.]47:1418", IPPort, "203.0.113.47:1418"},
		{"[2001:db8::1]:1224", IPPort, "[2001:db8::1]:1224"},
		{"::ffff:198.51.100.7", IP, "198.51.100.7"},
		{"hxxp://API.Example[.]com:1224/pdown#frag", URL, "http://api.example.com:1224/pdown"},
		{"Bad-Domain.Example.", Domain, "bad-domain.example"},
		{"c2.example:1418", Domain, "c2.example"},
		{"5C1F0F8F4B2F6D3A9E7C0B1A2D3E4F5061728394A5B6C7D8E9F0A1B2C3D4E5F6", SHA256, "5c1f0f8f4b2f6d3a9e7c0b1a2d3e4f5061728394a5b6c7d8e9f0a1b2c3d4e5f6"},
		{"d41d8cd98f00b204e9800998ecf8427e", MD5, "d41d8cd98f00b204e9800998ecf8427e"},
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if err != nil {
			t.Errorf("Parse(%q): %v", c.in, err)
			continue
		}
		if got.Kind != c.kind || got.Value != c.val {
			t.Errorf("Parse(%q) = %s %q, want %s %q", c.in, got.Kind, got.Value, c.kind, c.val)
		}
	}
	for _, bad := range []string{"", "not an indicator", "http://", "1.2.3", "deadbeef"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q): no error", bad)
		}
	}
}

func TestHostPortPath(t *testing.T) {
	u := MustParse("http://203.0.113.47:1224/uploads?x=1")
	if h, _ := u.Host(); h.Kind != IP || h.Value != "203.0.113.47" {
		t.Errorf("host = %+v", h)
	}
	if p, _ := u.Port(); p != 1224 {
		t.Errorf("port = %d", p)
	}
	if u.Path() != "/uploads" {
		t.Errorf("path = %q", u.Path())
	}
	if p, _ := MustParse("https://c2.example/x").Port(); p != 443 {
		t.Errorf("default https port = %d", p)
	}
}

func TestDefang(t *testing.T) {
	cases := map[string]string{
		"203.0.113.47":                        "203.0.113[.]47",
		"203.0.113.47:1418":                   "203.0.113[.]47:1418",
		"api.nodecheck-cdn.example":           "api.nodecheck-cdn[.]example",
		"http://203.0.113.47:1418/socket.io/": "hxxp://203.0.113[.]47:1418/socket.io/",
		"https://a.vercel.app/x.js":           "hxxps://a.vercel[.]app/x.js",
	}
	for in, want := range cases {
		if got := Defang(in); got != want {
			t.Errorf("Defang(%q) = %q, want %q", in, got, want)
		}
		if back := Refang(Defang(in)); back != in {
			t.Errorf("Refang(Defang(%q)) = %q", in, back)
		}
	}
}

func TestRoutable(t *testing.T) {
	for s, want := range map[string]bool{
		"203.0.113.47": true, // documentation, but used by the demo dataset
		"8.8.8.8":      true,
		"10.1.2.3":     false,
		"127.0.0.1":    false,
		"100.64.1.1":   false,
		"169.254.1.1":  false,
		"fe80::1":      false,
	} {
		if got := Routable(netip.MustParseAddr(s)); got != want {
			t.Errorf("Routable(%s) = %v", s, got)
		}
	}
}
