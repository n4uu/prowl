// Package score turns evidence into a probability per indicator.
//
// The model is naive-Bayes-style log-odds with two corrections that matter
// for threat intel:
//
//  1. Correlated evidence is damped. Two ThreatFox reports of the same IOC
//     are not two independent observations: reporters copy each other, and
//     ThreatFox and URLhaus share a community. Evidence is grouped (see the
//     profile) and within a group the strongest signal counts in full, the
//     second at group_decay, the third at group_decay^2, and so on.
//  2. Sightings decay. C2 addresses churn; an IP reported 18 months ago is
//     weak evidence about today. Dated evidence loses half its weight every
//     half_life_days. Structural evidence (a port, a path) doesn't decay.
//
// Association (guilt by infrastructure) is computed in a second pass from
// neighbours' *base* scores, the score from their own direct evidence. Using
// final scores would let two weak nodes vouch for each other in a loop.
package score

import (
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"sort"
	"time"

	"github.com/n4uu/prowl/internal/graph"
	"github.com/n4uu/prowl/internal/ioc"
	"github.com/n4uu/prowl/internal/profile"
)

// Tier names follow the estimative language of ICD 203, which is also what
// MISP's estimative-language taxonomy uses.
func Tier(p float64) string {
	switch {
	case p >= 0.95:
		return "almost-certain"
	case p >= 0.80:
		return "very-likely"
	case p >= 0.55:
		return "likely"
	case p >= 0.45:
		return "roughly-even-chance"
	case p >= 0.20:
		return "unlikely"
	case p >= 0.05:
		return "very-unlikely"
	}
	return "almost-no-chance"
}

// TierRank orders tiers so callers can filter with "at least likely".
func TierRank(t string) int {
	for i, n := range []string{"almost-no-chance", "very-unlikely", "unlikely", "roughly-even-chance", "likely", "very-likely", "almost-certain"} {
		if n == t {
			return i
		}
	}
	return -1
}

// associationFloor: neighbours below this base probability pass nothing on.
const associationFloor = 0.5

// Compute scores every node in g.
func Compute(g *graph.Graph, p *profile.Profile, now time.Time) {
	// Pass 0: structural and context evidence that follows from the value
	// itself, and exportability.
	for _, n := range g.Nodes {
		structural(n, p)
	}

	// Pass 1: base scores from direct evidence.
	for _, n := range g.Nodes {
		n.Base, _ = combine(n.Evidence, p, now)
	}

	// Pass 2: association from neighbours' base scores.
	assoc := map[string][]graph.Evidence{}
	for _, n := range g.Nodes {
		assoc[n.ID] = association(g, n, p)
	}
	for id, ev := range clusters(g, p) {
		assoc[id] = append(assoc[id], ev...)
	}

	for _, n := range g.Nodes {
		all := append(append([]graph.Evidence(nil), n.Evidence...), assoc[n.ID]...)
		n.P, n.Reasons = combine(all, p, now)
		n.Tier = Tier(n.P)
	}
}

func structural(n *graph.Node, p *profile.Profile) {
	i := n.IOC()
	if port, ok := i.Port(); ok && (n.Kind == ioc.IPPort || n.Kind == ioc.URL) {
		if why, ok := p.Ports[port]; ok {
			n.AddEvidence(graph.Evidence{Signal: "c2_port", Strength: 1, Source: "profile", Detail: fmt.Sprintf("port %d: %s", port, why)})
		}
	}
	if n.Kind == ioc.URL {
		if pp, why, ok := p.PathMatch(i.Path()); ok {
			n.AddEvidence(graph.Evidence{Signal: "c2_path", Strength: 1, Source: "profile", Detail: fmt.Sprintf("path %s: %s", pp, why)})
		}
		// A deep URL on a legitimate service (a repo, a paste) is a fine
		// indicator. Its front page is the whole service: ThreatFox has
		// "https://tronscan.org/" filed under this campaign because
		// EtherHiding loaders read from the TRON chain.
		if h, ok := i.Host(); ok && h.Kind == ioc.Domain && p.IsBenign(h.Value) && isRoot(n.Value) {
			n.AddEvidence(graph.Evidence{Signal: "benign_service", Strength: 1, Source: "profile", Detail: "front page of a well-known legitimate service"})
			n.Exportable, n.NoExport = false, "front page of a benign service"
		}
	}
	if n.Kind == ioc.Domain {
		if p.IsBenign(n.Value) {
			n.AddEvidence(graph.Evidence{Signal: "benign_service", Strength: 1, Source: "profile", Detail: "well-known legitimate service"})
			n.Exportable, n.NoExport = false, "benign service"
		} else if s, ok := p.Shared(n.Value); ok {
			n.AddEvidence(graph.Evidence{Signal: "shared_hosting", Strength: 1, Source: "profile", Detail: "subdomain of shared hosting " + s + "; the URL is the indicator, not the domain"})
			n.Exportable, n.NoExport = false, "shared hosting ("+s+")"
		}
	}
	if n.Kind == ioc.IP {
		if asn := n.Meta["asn"]; asn != "" {
			if name, ok := p.SharedASNs[asn]; ok {
				n.AddEvidence(graph.Evidence{Signal: "shared_hosting", Strength: 1, Source: "Team Cymru", Detail: fmt.Sprintf("AS%s (%s) fronts many unrelated sites", asn, name)})
				n.Exportable, n.NoExport = false, "CDN address (AS"+asn+" "+name+")"
			}
		}
	}
}

// relation maps an edge type to the evidence signal it carries.
var relation = map[string]string{
	"port-of":     "same_host",
	"serves":      "same_host",
	"hosts":       "co_hosted",
	"resolves-to": "resolves_to",
	"shares-cert": "shares_cert",
}

func association(g *graph.Graph, n *graph.Node, p *profile.Profile) []graph.Evidence {
	if isShared(n) {
		return nil
	}
	best := map[string]graph.Evidence{} // one per neighbour, strongest relation wins
	for _, e := range g.Neighbors(n.ID) {
		sig, ok := relation[e.Rel]
		if !ok {
			continue
		}
		nb := g.Nodes[e.To]
		if nb == nil || nb.Base < associationFloor || isShared(nb) {
			continue
		}
		strength := nb.Base
		detail := fmt.Sprintf("%s %s (base p=%.2f)", relPhrase(e.Rel, e.Rev), nb.Value, nb.Base)
		if e.Rel == "shares-cert" {
			// A cert covering 3 names says a lot; one covering 80 says the
			// names share a hosting panel. Dilute past 5 names.
			var sans int
			fmt.Sscanf(e.Detail, "%d", &sans)
			if sans > 5 {
				strength *= 5 / float64(sans)
			}
			detail += ", " + e.Detail
		}
		ev := graph.Evidence{Signal: sig, Strength: strength, Source: e.Source, Detail: detail, Neighbor: nb.ID}
		if have, ok := best[nb.ID]; !ok || have.Strength < ev.Strength {
			best[nb.ID] = ev
		}
	}
	out := make([]graph.Evidence, 0, len(best))
	for _, ev := range best {
		out = append(out, ev)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Neighbor < out[j].Neighbor })
	return out
}

// relPhrase describes the neighbour from this node's side of the edge.
func relPhrase(rel string, rev bool) string {
	switch rel {
	case "port-of":
		return "same host as"
	case "serves":
		if rev {
			return "served by"
		}
		return "serves"
	case "hosts":
		if rev {
			return "hosted on"
		}
		return "hosts"
	case "resolves-to":
		if rev {
			return "address of"
		}
		return "resolves to"
	case "shares-cert":
		return "shares a certificate with"
	}
	return rel
}

func isShared(n *graph.Node) bool { return !n.Exportable }

// isRoot reports whether a URL points at a site's front page: no path
// beyond "/", no query.
func isRoot(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return (u.Path == "" || u.Path == "/") && u.RawQuery == ""
}

// clusters adds same-/24 and same-ASN evidence to addresses (and their
// ip:port children) that sit next to strong nodes.
func clusters(g *graph.Graph, p *profile.Profile) map[string][]graph.Evidence {
	type member struct {
		id   string
		addr netip.Addr
		base float64
		asn  string
	}
	var ips []member
	for _, n := range g.Nodes {
		if n.Kind != ioc.IP || isShared(n) {
			continue
		}
		a, err := netip.ParseAddr(n.Value)
		if err != nil {
			continue
		}
		base := n.Base
		// An IP's strength includes its ports: 1.2.3.4 with 1.2.3.4:1418
		// on ThreatFox is a strong node even with no evidence of its own.
		for _, e := range g.Neighbors(n.ID) {
			if nb := g.Nodes[e.To]; nb != nil && e.Rel == "port-of" && nb.Base > base {
				base = nb.Base
			}
		}
		ips = append(ips, member{n.ID, a, base, n.Meta["asn"]})
	}

	strongPrefix := map[netip.Prefix][]string{}
	strongASN := map[string][]string{}
	for _, m := range ips {
		if m.base < 0.65 {
			continue
		}
		pf := ioc.Prefix24(m.addr)
		strongPrefix[pf] = append(strongPrefix[pf], m.addr.String())
		if m.asn != "" {
			strongASN[m.asn] = append(strongASN[m.asn], m.addr.String())
		}
	}

	out := map[string][]graph.Evidence{}
	for _, m := range ips {
		pf := ioc.Prefix24(m.addr)
		others := without(strongPrefix[pf], m.addr.String())
		if len(others) > 0 {
			out[m.id] = append(out[m.id], graph.Evidence{Signal: "same_prefix", Strength: 1, Source: "graph",
				Detail: fmt.Sprintf("%s also holds %s", pf, joinMax(others, 3))})
		}
		if m.asn != "" {
			others := without(strongASN[m.asn], m.addr.String())
			if len(others) >= 2 {
				out[m.id] = append(out[m.id], graph.Evidence{Signal: "asn_cluster", Strength: 1, Source: "Team Cymru",
					Detail: fmt.Sprintf("AS%s hosts %d other likely nodes in this hunt", m.asn, len(others))})
			}
		}
	}
	return out
}

func without(xs []string, x string) []string {
	var out []string
	for _, y := range xs {
		if y != x {
			out = append(out, y)
		}
	}
	sort.Strings(out)
	return out
}

func joinMax(xs []string, n int) string {
	if len(xs) <= n {
		return fmt.Sprint(xs)
	}
	return fmt.Sprintf("%v and %d more", xs[:n], len(xs)-n)
}

// combine folds evidence into a probability and the per-item reasons.
func combine(evs []graph.Evidence, p *profile.Profile, now time.Time) (float64, []graph.Reason) {
	s := p.Scoring
	var reasons []graph.Reason
	for _, e := range evs {
		w, ok := s.Evidence[e.Signal]
		if !ok {
			continue
		}
		strength := e.Strength
		if strength <= 0 {
			continue
		}
		// Strength scales the weight of evidence (the log of the ratio),
		// so confidence 50 is half the evidence of confidence 100, not a
		// slightly smaller ratio.
		pts := math.Log(w.LR) * strength
		if e.Seen != nil && pts > 0 {
			age := now.Sub(*e.Seen).Hours() / 24
			if age > 0 {
				pts *= math.Pow(0.5, age/s.HalfLifeDays)
			}
		}
		reasons = append(reasons, graph.Reason{Evidence: e, Group: w.Group, LR: math.Exp(pts), Points: pts})
	}

	// Damp positive evidence within each group; negative evidence (context
	// that lowers the score) always counts in full.
	byGroup := map[string][]int{}
	for i, r := range reasons {
		if r.Points > 0 {
			byGroup[r.Group] = append(byGroup[r.Group], i)
		}
	}
	for _, idx := range byGroup {
		sort.SliceStable(idx, func(a, b int) bool { return reasons[idx[a]].Points > reasons[idx[b]].Points })
		for rank, i := range idx {
			reasons[i].Points *= math.Pow(s.GroupDecay, float64(rank))
		}
	}

	logit := math.Log(s.Prior / (1 - s.Prior))
	for _, r := range reasons {
		logit += r.Points
	}
	sort.SliceStable(reasons, func(i, j int) bool { return math.Abs(reasons[i].Points) > math.Abs(reasons[j].Points) })
	return 1 / (1 + math.Exp(-logit)), reasons
}
