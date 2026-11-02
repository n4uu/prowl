package export

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strings"

	"github.com/n4uu/prowl/internal/graph"
	"github.com/n4uu/prowl/internal/ioc"
	"github.com/n4uu/prowl/internal/profile"
	"github.com/n4uu/prowl/internal/score"
)

// Text writes the hunt summary: what was found, how sure, and why.
func Text(w io.Writer, g *graph.Graph, opts Options) {
	opts.defaults()
	sel := Selected(g, opts)
	ids := 0
	for _, n := range sel {
		if score.TierRank(n.Tier) >= score.TierRank(opts.IDSTier) {
			ids++
		}
	}
	fmt.Fprintf(w, "profile %s, %s\n", g.Profile, g.Started.Format("2006-01-02 15:04 MST"))
	fmt.Fprintf(w, "%d nodes, %d edges; %d indicators at %s or above, %d at %s or above\n\n",
		len(g.Nodes), len(g.Edges), len(sel), opts.MinTier, ids, opts.IDSTier)

	fmt.Fprintf(w, "%-5s %-15s %-8s %-46s %-10s %s\n", "p", "tier", "type", "indicator", "last seen", "why")
	for _, n := range sel {
		why := ""
		if len(n.Reasons) > 0 {
			r := n.Reasons[0]
			why = fmt.Sprintf("%s: %s", r.Signal, r.Detail)
		}
		fmt.Fprintf(w, "%-5s %-15s %-8s %-46s %-10s %s\n", prob(n.P), n.Tier, n.Kind, trunc(ioc.Defang(n.Value), 46), day(n.LastSeen), trunc(why, 90))
	}

	var ctx []*graph.Node
	for _, n := range g.Sorted() {
		if !n.Exportable {
			ctx = append(ctx, n)
		}
	}
	if len(ctx) > 0 {
		fmt.Fprintln(w, "\nseen but not exported")
		for _, n := range ctx {
			fmt.Fprintf(w, "  %-8s %-40s %s\n", n.Kind, ioc.Defang(n.Value), n.NoExport)
		}
	}
	if len(g.Notes) > 0 {
		fmt.Fprintln(w, "\nnotes")
		for _, s := range g.Notes {
			fmt.Fprintf(w, "  %s\n", s)
		}
	}
}

// Explain writes the full scoring breakdown for one node.
func Explain(w io.Writer, g *graph.Graph, n *graph.Node, p *profile.Profile) {
	fmt.Fprintf(w, "%s  %s\n", n.Value, n.Kind)
	fmt.Fprintf(w, "p=%.3f (%s), base p=%.3f from its own evidence\n", n.P, n.Tier, n.Base)
	fmt.Fprintf(w, "found at depth %d: %s\n", n.Depth, n.Via)
	if !n.Exportable {
		fmt.Fprintf(w, "not exported: %s\n", n.NoExport)
	}
	if n.FirstSeen != nil {
		fmt.Fprintf(w, "seen %s to %s\n", day(n.FirstSeen), day(n.LastSeen))
	}
	if len(n.Malware) > 0 || len(n.Tags) > 0 {
		fmt.Fprintf(w, "malware %v  tags %v\n", n.Malware, n.Tags)
	}
	if len(n.Meta) > 0 {
		keys := make([]string, 0, len(n.Meta))
		for k := range n.Meta {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			parts = append(parts, k+"="+n.Meta[k])
		}
		fmt.Fprintf(w, "meta %s\n", strings.Join(parts, "  "))
	}

	prior := math.Log(p.Scoring.Prior / (1 - p.Scoring.Prior))
	fmt.Fprintf(w, "\n  %+6.2f  prior (p=%.2f)\n", prior, p.Scoring.Prior)
	total := prior
	for _, r := range n.Reasons {
		total += r.Points
		fmt.Fprintf(w, "  %+6.2f  %-16s %-15s LR %-6.3g %s\n", r.Points, r.Signal, "["+r.Group+"]", r.LR, r.Detail)
		src := r.Source
		if r.Ref != "" {
			src += "  " + r.Ref
		}
		if r.Seen != nil {
			src += "  seen " + r.Seen.Format("2006-01-02")
		}
		fmt.Fprintf(w, "  %6s  %-16s %-15s %s\n", "", "", "", src)
	}
	fmt.Fprintf(w, "  ------\n  %+6.2f  log-odds  ->  p=%.3f\n", total, n.P)

	nbs := g.Neighbors(n.ID)
	if len(nbs) > 0 {
		fmt.Fprintln(w, "\nneighbours")
		for _, e := range nbs {
			nb := g.Nodes[e.To]
			if nb == nil {
				continue
			}
			fmt.Fprintf(w, "  %-12s %-40s p=%.2f  (%s)\n", e.Rel, nb.Value, nb.P, e.Source)
		}
	}
}

// prob prints a probability without rounding 0.996 up to a certainty.
func prob(p float64) string {
	if p >= 0.995 {
		return ">.99"
	}
	return fmt.Sprintf("%.2f", p)
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
