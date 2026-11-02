package hunt

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/n4uu/prowl/internal/demo"
	"github.com/n4uu/prowl/internal/graph"
	"github.com/n4uu/prowl/internal/ioc"
	"github.com/n4uu/prowl/internal/profile"
	"github.com/n4uu/prowl/internal/score"
	"github.com/n4uu/prowl/internal/source"
)

var now = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

func demoHunter(t *testing.T) *Hunter {
	t.Helper()
	p, err := profile.Load("contagious-interview")
	if err != nil {
		t.Fatal(err)
	}
	d := demo.New(now)
	c := source.NewClient(source.NewMemCache(), false)
	c.HTTP = &http.Client{Transport: d.Transport()}
	c.MinInterval = nil
	dns := source.NewDNS(source.NewMemCache(), false)
	dns.R = d.Resolver()
	return &Hunter{
		Profile:   p,
		ThreatFox: &source.ThreatFox{C: c, Key: "demo"},
		URLhaus:   &source.URLhaus{C: c, Key: "demo"},
		CrtSh:     &source.CrtSh{C: c},
		DNS:       dns,
	}
}

func node(t *testing.T, g *graph.Graph, raw string) *graph.Node {
	t.Helper()
	n := g.Nodes[ioc.MustParse(raw).ID()]
	if n == nil {
		t.Fatalf("%s not in graph", raw)
	}
	return n
}

func atLeast(t *testing.T, n *graph.Node, tier string) {
	t.Helper()
	if score.TierRank(n.Tier) < score.TierRank(tier) {
		t.Errorf("%s: %s (p=%.3f), want at least %s; reasons %+v", n.Value, n.Tier, n.P, tier, n.Reasons)
	}
}

func atMost(t *testing.T, n *graph.Node, tier string) {
	t.Helper()
	if score.TierRank(n.Tier) > score.TierRank(tier) {
		t.Errorf("%s: %s (p=%.3f), want at most %s", n.Value, n.Tier, n.P, tier)
	}
}

func TestDemoHunt(t *testing.T) {
	g, err := demoHunter(t).Run(context.Background(), nil, Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}

	// Seeds straight from ThreatFox, recent and confident.
	atLeast(t, node(t, g, "203.0.113.47:1418"), "almost-certain")
	atLeast(t, node(t, g, "198.51.100.88:1224"), "almost-certain")
	// Found only by pivoting: URLhaus URL on a C2 port, the bare address,
	// a certificate sibling, the address the C2 domain resolves to.
	atLeast(t, node(t, g, "http://198.51.100.88:1224/keys"), "very-likely")
	atLeast(t, node(t, g, "203.0.113.47"), "very-likely")
	atLeast(t, node(t, g, "metrics.devhire-portal.example"), "likely")
	atLeast(t, node(t, g, "203.0.113.49"), "likely")

	// A 300-day-old, confidence-50 sighting has decayed.
	atMost(t, node(t, g, "198.51.100.89:1244"), "unlikely")
	// A 500-day-old one never got in (-since 365d).
	if _, ok := g.Nodes[ioc.MustParse("198.51.100.90:1244").ID()]; ok {
		t.Error("record older than -since was seeded")
	}

	// Context, never exported.
	for raw, why := range map[string]string{
		"assets-loader.vercel.app": "shared hosting",
		"github.com":               "benign",
		"192.0.2.80":               "CDN",
	} {
		n := node(t, g, raw)
		if n.Exportable || !strings.Contains(n.NoExport, why) {
			t.Errorf("%s: exportable=%v reason=%q", raw, n.Exportable, n.NoExport)
		}
	}
	// The vercel URL itself is an indicator even though its domain isn't.
	atLeast(t, node(t, g, "https://assets-loader.vercel.app/api/ipcheck"), "very-likely")
	// The CDN address passes nothing on to the domain that points at it,
	// and gets nothing from it.
	if n := node(t, g, "192.0.2.80"); n.P > 0.05 {
		t.Errorf("CDN address scored %.2f", n.P)
	}

	// The 61-name SaaS certificate was skipped, not pivoted through.
	if _, ok := g.Nodes[ioc.MustParse("tenant01.saas-panel.example").ID()]; ok {
		t.Error("pivoted through a shared certificate")
	}
	found := false
	for _, n := range g.Notes {
		if strings.Contains(n, "7000003") {
			found = true
		}
	}
	if !found {
		t.Errorf("no note about the skipped certificate: %v", g.Notes)
	}

	// Enrichment reached every address, including ones never expanded.
	if node(t, g, "192.0.2.15").Meta["asn"] != "64510" {
		t.Error("depth-limit address not enriched with ASN")
	}
}

func TestDemoHuntIsDeterministic(t *testing.T) {
	a, err := demoHunter(t).Run(context.Background(), nil, Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	b, err := demoHunter(t).Run(context.Background(), nil, Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Nodes) != len(b.Nodes) {
		t.Fatalf("%d vs %d nodes", len(a.Nodes), len(b.Nodes))
	}
	for id, n := range a.Nodes {
		if m := b.Nodes[id]; m == nil || m.P != n.P {
			t.Errorf("%s differs between runs", id)
		}
	}
}

func TestSeedOnlyNoProfile(t *testing.T) {
	h := demoHunter(t)
	g, err := h.Run(context.Background(), []ioc.IOC{ioc.MustParse("api.nodecheck-cdn.example")}, Options{Now: now, NoSeed: true, Depth: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := g.Nodes[ioc.MustParse("203.0.113.47:1418").ID()]; ok {
		t.Error("profile seeds queried despite NoSeed")
	}
	// depth 1 from the domain: its address and certificate siblings.
	node(t, g, "203.0.113.49")
	node(t, g, "nodecheck-cdn.example")
}

func TestMaxNodes(t *testing.T) {
	g, err := demoHunter(t).Run(context.Background(), nil, Options{Now: now, MaxNodes: 8})
	if err != nil {
		t.Fatal(err)
	}
	stopped := false
	for _, n := range g.Notes {
		stopped = stopped || strings.Contains(n, "max-nodes")
	}
	if !stopped {
		t.Errorf("no max-nodes note with %d nodes", len(g.Nodes))
	}
}
