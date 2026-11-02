// Package export writes a scored hunt graph as MISP, STIX 2.1, CSV or
// Graphviz.
package export

import (
	"crypto/sha1"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/n4uu/prowl/internal/graph"
	"github.com/n4uu/prowl/internal/ioc"
	"github.com/n4uu/prowl/internal/profile"
	"github.com/n4uu/prowl/internal/score"
)

// Options controls what gets exported.
type Options struct {
	MinTier  string // lowest tier to include (default "likely")
	IDSTier  string // lowest tier flagged for detection/blocking (default "very-likely")
	TLP      string // clear, green, amber, amber+strict, red (default amber)
	Producer string // identity name for STIX created_by_ref (default "prowl")
	Now      time.Time
}

func (o *Options) defaults() {
	if o.MinTier == "" {
		o.MinTier = "likely"
	}
	if o.IDSTier == "" {
		o.IDSTier = "very-likely"
	}
	if o.TLP == "" {
		o.TLP = "amber"
	}
	if o.Producer == "" {
		o.Producer = "prowl"
	}
	if o.Now.IsZero() {
		o.Now = time.Now().UTC()
	}
}

// Selected returns the exportable nodes at or above the minimum tier.
func Selected(g *graph.Graph, opts Options) []*graph.Node {
	opts.defaults()
	min := score.TierRank(opts.MinTier)
	var out []*graph.Node
	for _, n := range g.Sorted() {
		if n.Exportable && score.TierRank(n.Tier) >= min {
			out = append(out, n)
		}
	}
	return out
}

// Summary is a one-line explanation of a node's score: its top reasons.
func Summary(n *graph.Node, max int) string {
	var parts []string
	for i, r := range n.Reasons {
		if i >= max {
			break
		}
		parts = append(parts, fmt.Sprintf("%s %+.1f: %s", r.Signal, r.Points, r.Detail))
	}
	return strings.Join(parts, "; ")
}

// ---------------------------------------------------------------------------
// CSV

// CSV writes one row per selected indicator.
func CSV(w io.Writer, g *graph.Graph, opts Options) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"type", "value", "probability", "tier", "first_seen", "last_seen", "malware", "tags", "asn", "depth", "via", "reasons"})
	for _, n := range Selected(g, opts) {
		_ = cw.Write([]string{
			string(n.Kind), n.Value, fmt.Sprintf("%.3f", n.P), n.Tier,
			day(n.FirstSeen), day(n.LastSeen),
			strings.Join(n.Malware, "|"), strings.Join(n.Tags, "|"), n.Meta["asn"],
			fmt.Sprint(n.Depth), n.Via, Summary(n, 3),
		})
	}
	cw.Flush()
	return cw.Error()
}

func day(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format("2006-01-02")
}

// ---------------------------------------------------------------------------
// MISP

type mispTag struct {
	Name string `json:"name"`
}

type mispAttr struct {
	UUID      string    `json:"uuid"`
	Type      string    `json:"type"`
	Category  string    `json:"category"`
	Value     string    `json:"value"`
	ToIDS     bool      `json:"to_ids"`
	Comment   string    `json:"comment,omitempty"`
	FirstSeen string    `json:"first_seen,omitempty"`
	LastSeen  string    `json:"last_seen,omitempty"`
	Tag       []mispTag `json:"Tag,omitempty"`
}

type mispEvent struct {
	UUID          string     `json:"uuid"`
	Info          string     `json:"info"`
	Date          string     `json:"date"`
	ThreatLevelID string     `json:"threat_level_id"`
	Analysis      string     `json:"analysis"`
	Distribution  string     `json:"distribution"`
	Published     bool       `json:"published"`
	Tag           []mispTag  `json:"Tag"`
	Attribute     []mispAttr `json:"Attribute"`
}

// MISP writes a MISP event (the {"Event": {...}} form accepted by
// /events/add and by the import UI). Attribute UUIDs are derived from the
// profile and value, so re-importing a later hunt updates rather than
// duplicates.
func MISP(w io.Writer, g *graph.Graph, p *profile.Profile, opts Options) error {
	opts.defaults()
	ids := score.TierRank(opts.IDSTier)
	ev := mispEvent{
		UUID:          uuid5(nsProwl, "misp-event|"+p.Name+"|"+opts.Now.Format("2006-01-02")),
		Info:          fmt.Sprintf("%s infrastructure (prowl hunt, %s)", p.Actor.Name, opts.Now.Format("2006-01-02")),
		Date:          opts.Now.Format("2006-01-02"),
		ThreatLevelID: "2",
		Analysis:      "1",
		Distribution:  "0",
		// Only standard taxonomies here. Galaxy clusters for the actor and
		// families differ between MISP instances; attach them on import.
		Tag: []mispTag{
			{"tlp:" + opts.TLP},
			{"type:OSINT"},
		},
	}

	for _, n := range Selected(g, opts) {
		typ, cat, val := mispType(n)
		if typ == "" {
			continue
		}
		a := mispAttr{
			UUID:     uuid5(nsProwl, "misp-attr|"+p.Name+"|"+n.ID),
			Type:     typ,
			Category: cat,
			Value:    val,
			ToIDS:    score.TierRank(n.Tier) >= ids,
			Comment:  comment(n),
			Tag:      []mispTag{{`estimative-language:likelihood-probability="` + n.Tier + `"`}},
		}
		if n.FirstSeen != nil {
			a.FirstSeen = n.FirstSeen.Format(time.RFC3339)
		}
		if n.LastSeen != nil {
			a.LastSeen = n.LastSeen.Format(time.RFC3339)
		}
		ev.Attribute = append(ev.Attribute, a)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{"Event": ev})
}

func comment(n *graph.Node) string {
	c := fmt.Sprintf("p=%s %s", prob(n.P), n.Tier)
	if len(n.Malware) > 0 {
		c += " [" + strings.Join(n.Malware, ", ") + "]"
	}
	return c + ". " + Summary(n, 3)
}

func mispType(n *graph.Node) (typ, category, value string) {
	switch n.Kind {
	case ioc.IPPort:
		host, port, _ := strings.Cut(n.Value, ":")
		if strings.HasPrefix(n.Value, "[") { // [v6]:port
			i := strings.LastIndex(n.Value, "]:")
			host, port = n.Value[1:i], n.Value[i+2:]
		}
		return "ip-dst|port", "Network activity", host + "|" + port
	case ioc.IP:
		return "ip-dst", "Network activity", n.Value
	case ioc.Domain:
		return "domain", "Network activity", n.Value
	case ioc.URL:
		return "url", "Network activity", n.Value
	case ioc.SHA256:
		return "sha256", "Payload delivery", n.Value
	case ioc.MD5:
		return "md5", "Payload delivery", n.Value
	}
	return "", "", ""
}

// ---------------------------------------------------------------------------
// STIX 2.1

// nsProwl namespaces the UUIDv5 ids prowl derives for SDOs and MISP objects.
var nsProwl = mustUUID("6f1c2b0e-8d7a-5e44-9b3f-2a6d1e0c9f57")

// nsSTIX is the namespace STIX 2.1 section 2.9 mandates for deterministic
// cyber-observable ids.
var nsSTIX = mustUUID("00abedb4-aa42-466c-9c01-fed23315a9b7")

// STIX writes a STIX 2.1 bundle: an identity, the intrusion set, one
// malware SDO per family, and for each selected indicator an indicator SDO,
// the observable it describes, and the relationships between them. SCO ids
// follow the spec's deterministic scheme so the same address always gets
// the same id, whoever produced it.
func STIX(w io.Writer, g *graph.Graph, p *profile.Profile, opts Options) error {
	opts.defaults()
	ts := opts.Now.Format("2006-01-02T15:04:05.000Z")
	var objs []map[string]any
	seen := map[string]bool{}
	// An address can be both an ip indicator and the host of an ip:port
	// one; its observable (same deterministic id) goes in once.
	add := func(o map[string]any) {
		id := o["id"].(string)
		if seen[id] {
			return
		}
		seen[id] = true
		objs = append(objs, o)
	}

	identity := "identity--" + uuid5(nsProwl, "identity|"+opts.Producer)
	add(map[string]any{
		"type": "identity", "spec_version": "2.1", "id": identity,
		"created": ts, "modified": ts, "name": opts.Producer, "identity_class": "individual",
	})
	marking := tlpMarking(opts.TLP)

	sdo := func(typ, key string, extra map[string]any) string {
		id := typ + "--" + uuid5(nsProwl, typ+"|"+p.Name+"|"+key)
		o := map[string]any{"type": typ, "spec_version": "2.1", "id": id, "created": ts, "modified": ts, "created_by_ref": identity}
		if marking != "" {
			o["object_marking_refs"] = []string{marking}
		}
		for k, v := range extra {
			o[k] = v
		}
		add(o)
		return id
	}
	rel := func(src, typ, dst string) {
		sdo("relationship", src+"|"+typ+"|"+dst, map[string]any{"relationship_type": typ, "source_ref": src, "target_ref": dst})
	}

	iset := sdo("intrusion-set", p.Actor.Name, map[string]any{
		"name": p.Actor.Name, "aliases": p.Actor.Aliases, "description": strings.TrimSpace(p.Description),
	})
	// A family can be listed once per ThreatFox name (BeaverTail is filed
	// as js., win. and osx.); STIX gets one malware object per family,
	// with the Malpedia link from whichever entry has one.
	malwareIDs := map[string]string{}
	malpedia := map[string]string{}
	for _, f := range p.Families {
		if malpedia[f.Name] == "" {
			malpedia[f.Name] = f.Malpedia
		}
	}
	for _, f := range p.Families {
		if _, done := malwareIDs[f.Name]; done {
			continue
		}
		props := map[string]any{
			"name": f.Name, "is_family": true,
			"malware_types": []string{"backdoor", "remote-access-trojan"},
		}
		if u := malpedia[f.Name]; u != "" {
			props["external_references"] = []map[string]string{{"source_name": "malpedia", "url": u}}
		}
		id := sdo("malware", f.Name, props)
		malwareIDs[f.Name] = id
		rel(iset, "uses", id)
	}

	for _, n := range Selected(g, opts) {
		pattern, scos := stixPattern(n)
		if pattern == "" {
			continue
		}
		for _, s := range scos {
			add(s)
		}
		valid := ts
		if n.FirstSeen != nil {
			valid = n.FirstSeen.Format("2006-01-02T15:04:05.000Z")
		}
		ind := sdo("indicator", n.ID, map[string]any{
			"name":            fmt.Sprintf("%s %s", n.Kind, ioc.Defang(n.Value)),
			"description":     Summary(n, 4),
			"indicator_types": []string{"malicious-activity"},
			"pattern":         pattern,
			"pattern_type":    "stix",
			"valid_from":      valid,
			"confidence":      int(n.P*100 + 0.5),
			"labels":          []string{n.Tier},
		})
		rel(ind, "indicates", iset)
		for _, m := range n.Malware {
			if id, ok := malwareIDs[m]; ok {
				rel(ind, "indicates", id)
			}
		}
		if n.Kind == ioc.IPPort || n.Kind == ioc.IP || n.Kind == ioc.Domain || n.Kind == ioc.URL {
			infra := sdo("infrastructure", n.ID, map[string]any{
				"name": ioc.Defang(n.Value), "infrastructure_types": []string{"command-and-control"},
			})
			for _, s := range scos {
				rel(infra, "consists-of", s["id"].(string))
			}
			rel(iset, "uses", infra)
			rel(ind, "indicates", infra)
		}
	}

	sort.SliceStable(objs, func(i, j int) bool { return typeOrder(objs[i]["type"].(string)) < typeOrder(objs[j]["type"].(string)) })
	bundle := map[string]any{
		"type":    "bundle",
		"id":      "bundle--" + uuid5(nsProwl, "bundle|"+p.Name+"|"+ts),
		"objects": objs,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(bundle)
}

func typeOrder(t string) int {
	for i, x := range []string{"identity", "marking-definition", "intrusion-set", "malware", "indicator", "infrastructure", "ipv4-addr", "ipv6-addr", "domain-name", "url", "file", "relationship"} {
		if x == t {
			return i
		}
	}
	return 99
}

// stixPattern returns the indicator pattern and the observables it covers.
func stixPattern(n *graph.Node) (string, []map[string]any) {
	sco := func(typ string, props map[string]any, key string) map[string]any {
		o := map[string]any{"type": typ, "spec_version": "2.1", "id": typ + "--" + uuid5(nsSTIX, key)}
		for k, v := range props {
			o[k] = v
		}
		return o
	}
	ipType := func(v string) string {
		if strings.Contains(v, ":") {
			return "ipv6-addr"
		}
		return "ipv4-addr"
	}
	switch n.Kind {
	case ioc.IP:
		t := ipType(n.Value)
		return fmt.Sprintf("[%s:value = '%s']", t, n.Value),
			[]map[string]any{sco(t, map[string]any{"value": n.Value}, canonical("value", n.Value))}
	case ioc.IPPort:
		host, _ := n.IOC().Host()
		port, _ := n.IOC().Port()
		t := ipType(host.Value)
		return fmt.Sprintf("[network-traffic:dst_ref.type = '%s' AND network-traffic:dst_ref.value = '%s' AND network-traffic:dst_port = %d]", t, host.Value, port),
			[]map[string]any{sco(t, map[string]any{"value": host.Value}, canonical("value", host.Value))}
	case ioc.Domain:
		return fmt.Sprintf("[domain-name:value = '%s']", n.Value),
			[]map[string]any{sco("domain-name", map[string]any{"value": n.Value}, canonical("value", n.Value))}
	case ioc.URL:
		v := strings.ReplaceAll(n.Value, "'", "\\'")
		return fmt.Sprintf("[url:value = '%s']", v),
			[]map[string]any{sco("url", map[string]any{"value": n.Value}, canonical("value", n.Value))}
	case ioc.SHA256:
		return fmt.Sprintf("[file:hashes.'SHA-256' = '%s']", n.Value), nil
	case ioc.MD5:
		return fmt.Sprintf("[file:hashes.MD5 = '%s']", n.Value), nil
	}
	return "", nil
}

// canonical renders {"k":"v"} the way RFC 8785 JCS would for a single
// string property, which is what the STIX deterministic id hashes.
func canonical(k, v string) string {
	kb, _ := json.Marshal(k)
	vb, _ := json.Marshal(v)
	return "{" + string(kb) + ":" + string(vb) + "}"
}

// tlpMarking returns the TLP marking-definition ids fixed by the STIX 2.1
// specification (section 7.2.1.4). They are well known, so the definitions
// themselves don't need to travel in the bundle. TLP 2.0's CLEAR maps to
// WHITE and AMBER+STRICT to AMBER, the closest 1.0 equivalents.
func tlpMarking(tlp string) string {
	switch strings.ToLower(tlp) {
	case "clear", "white":
		return "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
	case "green":
		return "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
	case "amber", "amber+strict":
		return "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
	case "red":
		return "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"
	}
	return ""
}

// ---------------------------------------------------------------------------
// Graphviz

// DOT writes the graph for `dot -Tsvg`. Node colour follows the tier.
func DOT(w io.Writer, g *graph.Graph, opts Options) error {
	opts.defaults()
	fmt.Fprintln(w, "digraph prowl {")
	fmt.Fprintln(w, `  graph [rankdir=LR, fontname="Helvetica", bgcolor="white"];`)
	fmt.Fprintln(w, `  node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=10];`)
	fmt.Fprintln(w, `  edge [fontname="Helvetica", fontsize=8, color="#888888"];`)
	shown := map[string]bool{}
	for _, n := range g.Sorted() {
		if score.TierRank(n.Tier) < score.TierRank("unlikely") && n.Depth > 0 {
			continue
		}
		shown[n.ID] = true
		fmt.Fprintf(w, "  %q [label=%q, fillcolor=%q];\n", n.ID, fmt.Sprintf("%s\n%s p=%.2f", ioc.Defang(n.Value), n.Kind, n.P), color(n))
	}
	for _, e := range g.Edges {
		if shown[e.From] && shown[e.To] {
			fmt.Fprintf(w, "  %q -> %q [label=%q];\n", e.From, e.To, e.Rel)
		}
	}
	fmt.Fprintln(w, "}")
	return nil
}

func color(n *graph.Node) string {
	if !n.Exportable {
		return "#e0e0e0"
	}
	switch n.Tier {
	case "almost-certain":
		return "#d73027"
	case "very-likely":
		return "#fc8d59"
	case "likely":
		return "#fee090"
	case "roughly-even-chance":
		return "#e0f3f8"
	}
	return "#f7f7f7"
}

// ---------------------------------------------------------------------------
// UUIDs

type uuid [16]byte

func mustUUID(s string) uuid {
	var u uuid
	hex := strings.ReplaceAll(s, "-", "")
	if len(hex) != 32 {
		panic("bad uuid " + s)
	}
	for i := 0; i < 16; i++ {
		fmt.Sscanf(hex[2*i:2*i+2], "%02x", &u[i])
	}
	return u
}

// uuid5 is RFC 4122 name-based (SHA-1) UUID.
func uuid5(ns uuid, name string) string {
	h := sha1.New()
	h.Write(ns[:])
	h.Write([]byte(name))
	s := h.Sum(nil)
	s[6] = (s[6] & 0x0f) | 0x50
	s[8] = (s[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", s[0:4], s[4:6], s[6:8], s[8:10], s[10:16])
}
