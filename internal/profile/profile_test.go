package profile

import "testing"

func TestBuiltin(t *testing.T) {
	p, err := Load("contagious-interview")
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := p.FamilyFor("JS.OTTER_COOKIE"); !ok || f.Name != "OtterCookie" {
		t.Errorf("FamilyFor = %+v %v", f, ok)
	}
	if p.Ports[1418] == "" || p.Scoring.Evidence["threatfox_family"].LR <= 1 {
		t.Error("ports or weights missing")
	}
	got := p.MatchTags([]string{"contagious-interview", "OTTERCOOKIE", "unrelated", "Contagious Interview"})
	if len(got) != 2 || got[0] != "ContagiousInterview" || got[1] != "OtterCookie" {
		t.Errorf("MatchTags = %v", got)
	}
	for path, want := range map[string]string{"/pdown": "/pdown", "/pdown/x": "/pdown", "/pdownload": "", "/socket.io/": "/socket.io/", "/socket.io/x": "/socket.io/", "/socket.iox": "", "/uploads": "/uploads"} {
		pp, _, _ := p.PathMatch(path)
		if pp != want {
			t.Errorf("PathMatch(%q) = %q, want %q", path, pp, want)
		}
	}
	if _, ok := p.Shared("assets-loader.vercel.app"); !ok {
		t.Error("vercel.app not shared")
	}
	if _, ok := p.Shared("notvercel.app"); ok {
		t.Error("suffix match without a dot boundary")
	}
	if !p.IsBenign("registry.npmjs.org") || p.IsBenign("npmjs.org.evil.example") {
		t.Error("benign matching wrong")
	}
	if p.SharedASNs["13335"] == "" {
		t.Error("Cloudflare missing from shared_asns")
	}
}

func TestRejectsBadProfiles(t *testing.T) {
	cases := map[string]string{
		"unknown field": "name: x\nscoring: {prior: 0.1}\ntypo_field: 1\n",
		"no name":       "scoring: {prior: 0.1}\n",
		"bad prior":     "name: x\nscoring: {prior: 1.5}\n",
		"zero lr":       "name: x\nscoring: {prior: 0.1, evidence: {a: {lr: 0, group: g}}}\n",
		"no group":      "name: x\nscoring: {prior: 0.1, evidence: {a: {lr: 2}}}\n",
	}
	for name, y := range cases {
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
