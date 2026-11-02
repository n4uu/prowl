// Package graph holds what a hunt found: indicators, how they connect, and
// the evidence attached to each.
package graph

import (
	"encoding/json"
	"io"
	"sort"
	"time"

	"github.com/n4uu/prowl/internal/ioc"
)

// Evidence is one observation about a node, before scoring.
type Evidence struct {
	Signal   string     `json:"signal"`             // key into profile.scoring.evidence
	Strength float64    `json:"strength"`           // 0..1 multiplier on the signal's weight
	Seen     *time.Time `json:"seen,omitempty"`     // when it was observed, for decay
	Source   string     `json:"source"`             // where it came from (ThreatFox #123, crt.sh 456)
	Detail   string     `json:"detail"`             // human-readable
	Ref      string     `json:"ref,omitempty"`      // a link to the source record
	Neighbor string     `json:"neighbor,omitempty"` // for association evidence
}

// Reason is a scored piece of evidence: how many log-odds points it added.
type Reason struct {
	Evidence
	Group  string  `json:"group"`
	LR     float64 `json:"lr"`     // effective likelihood ratio
	Points float64 `json:"points"` // natural-log odds after decay and group damping
}

// Node is one indicator.
type Node struct {
	ID        string            `json:"id"`
	Kind      ioc.Kind          `json:"kind"`
	Value     string            `json:"value"`
	Depth     int               `json:"depth"`
	Via       string            `json:"via"`
	Malware   []string          `json:"malware,omitempty"`
	Tags      []string          `json:"tags,omitempty"`
	FirstSeen *time.Time        `json:"first_seen,omitempty"`
	LastSeen  *time.Time        `json:"last_seen,omitempty"`
	Meta      map[string]string `json:"meta,omitempty"`
	Evidence  []Evidence        `json:"evidence,omitempty"`

	Base    float64  `json:"base_probability"`
	P       float64  `json:"probability"`
	Tier    string   `json:"tier"`
	Reasons []Reason `json:"reasons,omitempty"`
	// Exportable is false for things that are context, not indicators:
	// a shared-hosting domain, a benign service, a CDN address.
	Exportable bool   `json:"exportable"`
	NoExport   string `json:"no_export_reason,omitempty"`
}

// IOC returns the node as an indicator.
func (n *Node) IOC() ioc.IOC { return ioc.IOC{Kind: n.Kind, Value: n.Value} }

// Edge is a relation between two nodes.
type Edge struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Rel    string `json:"rel"` // port-of, hosts, resolves-to, shares-cert, reported-with
	Source string `json:"source"`
	Detail string `json:"detail,omitempty"`
	// Rev is set on edges returned by Neighbors when the stored edge points
	// the other way, so callers can phrase "served by" vs "serves".
	Rev bool `json:"-"`
}

// Graph is the result of a hunt.
type Graph struct {
	Profile  string           `json:"profile"`
	Started  time.Time        `json:"started"`
	Finished time.Time        `json:"finished"`
	Seeds    []string         `json:"seeds"`
	Notes    []string         `json:"notes,omitempty"`
	Stats    map[string]any   `json:"stats,omitempty"`
	Nodes    map[string]*Node `json:"nodes"`
	Edges    []Edge           `json:"edges"`

	order []string
	edges map[string]bool
}

// New returns an empty graph.
func New(profile string) *Graph {
	return &Graph{Profile: profile, Nodes: map[string]*Node{}, edges: map[string]bool{}}
}

// Add inserts an indicator, or returns the existing node. A node keeps the
// smallest depth it was reached at.
func (g *Graph) Add(i ioc.IOC, depth int, via string) (*Node, bool) {
	id := i.ID()
	if n, ok := g.Nodes[id]; ok {
		if depth < n.Depth {
			n.Depth, n.Via = depth, via
		}
		return n, false
	}
	n := &Node{ID: id, Kind: i.Kind, Value: i.Value, Depth: depth, Via: via, Meta: map[string]string{}, Exportable: true}
	g.Nodes[id] = n
	g.order = append(g.order, id)
	return n, true
}

// symmetric relations are stored once whichever end found them.
var symmetric = map[string]bool{"shares-cert": true}

// Link records a relation once.
func (g *Graph) Link(from, to, rel, source, detail string) {
	if from == to {
		return
	}
	if symmetric[rel] && to < from {
		from, to = to, from
	}
	k := from + "\x00" + to + "\x00" + rel
	if g.edges == nil {
		g.edges = map[string]bool{}
	}
	if g.edges[k] {
		return
	}
	g.edges[k] = true
	g.Edges = append(g.Edges, Edge{From: from, To: to, Rel: rel, Source: source, Detail: detail})
}

// Neighbors returns the edges touching id, with the other end first.
func (g *Graph) Neighbors(id string) []Edge {
	var out []Edge
	for _, e := range g.Edges {
		switch id {
		case e.From:
			out = append(out, e)
		case e.To:
			out = append(out, Edge{From: e.To, To: e.From, Rel: e.Rel, Source: e.Source, Detail: e.Detail, Rev: true})
		}
	}
	return out
}

// Sorted returns nodes by probability, then kind, then value.
func (g *Graph) Sorted() []*Node {
	out := make([]*Node, 0, len(g.Nodes))
	for _, n := range g.Nodes {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].P != out[j].P {
			return out[i].P > out[j].P
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Value < out[j].Value
	})
	return out
}

// AddEvidence appends evidence, skipping exact duplicates (the same
// ThreatFox record reached through two queries).
func (n *Node) AddEvidence(e Evidence) {
	for _, have := range n.Evidence {
		if have.Signal == e.Signal && have.Source == e.Source && have.Detail == e.Detail {
			return
		}
	}
	n.Evidence = append(n.Evidence, e)
}

// Observe widens the node's first/last seen window.
func (n *Node) Observe(t time.Time) {
	if t.IsZero() {
		return
	}
	if n.FirstSeen == nil || t.Before(*n.FirstSeen) {
		tt := t
		n.FirstSeen = &tt
	}
	if n.LastSeen == nil || t.After(*n.LastSeen) {
		tt := t
		n.LastSeen = &tt
	}
}

// AddUnique appends s to a string set slice.
func AddUnique(xs []string, s string) []string {
	if s == "" {
		return xs
	}
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	return append(xs, s)
}

// Save writes the graph as JSON.
func (g *Graph) Save(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(g)
}

// Load reads a graph written by Save.
func Load(r io.Reader) (*Graph, error) {
	var g Graph
	if err := json.NewDecoder(r).Decode(&g); err != nil {
		return nil, err
	}
	g.edges = map[string]bool{}
	for _, e := range g.Edges {
		g.edges[e.From+"\x00"+e.To+"\x00"+e.Rel] = true
	}
	for id := range g.Nodes {
		g.order = append(g.order, id)
	}
	sort.Strings(g.order)
	return &g, nil
}
