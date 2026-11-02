package export

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/n4uu/prowl/internal/graph"
	"github.com/n4uu/prowl/internal/ioc"
	"github.com/n4uu/prowl/internal/profile"
)

func TestUUID5(t *testing.T) {
	// RFC 4122 / Python docs example: uuid5(NAMESPACE_DNS, "python.org")
	ns := mustUUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
	if got := uuid5(ns, "python.org"); got != "886313e1-3b8a-5372-9b90-0c9aee199e5d" {
		t.Errorf("uuid5 = %s", got)
	}
}

func TestSTIXDeterministicObservableIDs(t *testing.T) {
	// Reference values from the OASIS stix2 Python library.
	cases := map[string]string{
		"203.0.113.47":              "ipv4-addr--2192bd45-4d01-5fde-a772-f656b871a0fb",
		"api.nodecheck-cdn.example": "domain-name--6e36a514-d660-565a-b047-776c12cd0408",
	}
	for v, want := range cases {
		n := &graph.Node{Kind: ioc.MustParse(v).Kind, Value: v}
		_, scos := stixPattern(n)
		if len(scos) != 1 || scos[0]["id"] != want {
			t.Errorf("%s: id %v, want %s", v, scos, want)
		}
	}
}

func sample() (*graph.Graph, *profile.Profile) {
	p, _ := profile.Load("contagious-interview")
	g := graph.New(p.Name)
	add := func(raw string, prob float64, tier string, exportable bool) {
		n, _ := g.Add(ioc.MustParse(raw), 0, "test")
		n.P, n.Tier, n.Exportable = prob, tier, exportable
		n.Malware = []string{"OtterCookie"}
	}
	add("203.0.113.47:1418", 0.99, "almost-certain", true)
	add("[2001:db8::5]:1224", 0.9, "very-likely", true)
	add("c2.example", 0.6, "likely", true)
	add("weak.example", 0.3, "unlikely", true)
	add("assets.vercel.app", 0.9, "very-likely", false)
	return g, p
}

func TestMISP(t *testing.T) {
	g, p := sample()
	var buf bytes.Buffer
	if err := MISP(&buf, g, p, Options{Now: time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)}); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Event struct {
			Attribute []struct {
				Type, Value string
				ToIDS       bool `json:"to_ids"`
				Tag         []struct{ Name string }
			}
		}
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, a := range doc.Event.Attribute {
		got[a.Type+" "+a.Value] = a.ToIDS
		if !strings.Contains(a.Tag[0].Name, "estimative-language:likelihood-probability") {
			t.Errorf("missing estimative tag on %s", a.Value)
		}
	}
	want := map[string]bool{
		"ip-dst|port 203.0.113.47|1418": true,
		"ip-dst|port 2001:db8::5|1224":  true,
		"domain c2.example":             false, // likely: exported, not flagged for IDS
	}
	if len(got) != len(want) {
		t.Errorf("attributes = %v", got)
	}
	for k, ids := range want {
		if v, ok := got[k]; !ok || v != ids {
			t.Errorf("%s: present=%v to_ids=%v", k, ok, v)
		}
	}
}

func TestSTIXBundleShape(t *testing.T) {
	g, p := sample()
	var buf bytes.Buffer
	if err := STIX(&buf, g, p, Options{TLP: "clear"}); err != nil {
		t.Fatal(err)
	}
	var b struct {
		Type    string
		Objects []map[string]any
	}
	if err := json.Unmarshal(buf.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	count := map[string]int{}
	ids := map[string]bool{}
	for _, o := range b.Objects {
		count[o["type"].(string)]++
		id := o["id"].(string)
		if ids[id] {
			t.Errorf("duplicate id %s", id)
		}
		ids[id] = true
		if o["type"] == "indicator" {
			if c, _ := o["confidence"].(float64); c < 55 {
				t.Errorf("indicator below the export tier: %v", o["name"])
			}
		}
	}
	if count["indicator"] != 3 || count["malware"] != 3 || count["intrusion-set"] != 1 || count["ipv6-addr"] != 1 {
		t.Errorf("object counts %v", count)
	}
	for _, o := range b.Objects {
		if o["type"] != "relationship" {
			continue
		}
		for _, k := range []string{"source_ref", "target_ref"} {
			if !ids[o[k].(string)] {
				t.Errorf("dangling %s %v", k, o[k])
			}
		}
	}
}

func TestCSVAndDOT(t *testing.T) {
	g, _ := sample()
	var csvBuf, dot bytes.Buffer
	if err := CSV(&csvBuf, g, Options{MinTier: "unlikely"}); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(csvBuf.String(), "\n"); lines != 5 { // header + 4 exportable
		t.Errorf("csv has %d lines:\n%s", lines, csvBuf.String())
	}
	DOT(&dot, g, Options{})
	if !strings.HasPrefix(dot.String(), "digraph prowl {") || !strings.Contains(dot.String(), "203.0.113[.]47:1418") {
		t.Errorf("dot output:\n%s", dot.String())
	}
}
