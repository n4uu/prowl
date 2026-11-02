// Package hunt runs the pivot loop: seed from a campaign profile and/or
// known indicators, expand breadth-first through public telemetry, then
// score.
package hunt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/n4uu/prowl/internal/graph"
	"github.com/n4uu/prowl/internal/ioc"
	"github.com/n4uu/prowl/internal/probe"
	"github.com/n4uu/prowl/internal/profile"
	"github.com/n4uu/prowl/internal/score"
	"github.com/n4uu/prowl/internal/source"
)

// Options bounds a hunt.
type Options struct {
	Depth    int           // pivot hops from a seed (default 2)
	MaxNodes int           // stop expanding past this many nodes (default 400)
	Since    time.Duration // ignore ThreatFox seed records older than this (default 365d)
	Limit    int           // records per ThreatFox seed query (default 1000)
	MaxSANs  int           // skip certificates with more names than this (default 25)
	NoSeed   bool          // don't query the profile's families and tags
	Active   bool          // probe ip:port nodes for a live Engine.IO server
	Now      time.Time
	Log      io.Writer
}

func (o *Options) defaults() {
	if o.Depth == 0 {
		o.Depth = 2
	}
	if o.MaxNodes == 0 {
		o.MaxNodes = 400
	}
	if o.Since == 0 {
		o.Since = 365 * 24 * time.Hour
	}
	if o.Limit == 0 {
		o.Limit = 1000
	}
	if o.MaxSANs == 0 {
		o.MaxSANs = 25
	}
	if o.Now.IsZero() {
		o.Now = time.Now().UTC()
	}
	if o.Log == nil {
		o.Log = io.Discard
	}
}

// Hunter wires the sources together. Any source may be nil; the hunt
// simply doesn't pivot through it.
type Hunter struct {
	Profile   *profile.Profile
	ThreatFox *source.ThreatFox
	URLhaus   *source.URLhaus
	CrtSh     *source.CrtSh
	DNS       *source.DNS
	Prober    *probe.Prober

	opts  Options
	g     *graph.Graph
	queue []*graph.Node
	notes map[string]bool
}

// Run executes the hunt and returns the scored graph.
func (h *Hunter) Run(ctx context.Context, seeds []ioc.IOC, opts Options) (*graph.Graph, error) {
	opts.defaults()
	h.opts = opts
	h.g = graph.New(h.Profile.Name)
	h.g.Started = opts.Now
	h.notes = map[string]bool{}

	if !opts.NoSeed {
		if err := h.seedFromProfile(ctx); err != nil {
			return nil, err
		}
	}
	for _, s := range seeds {
		h.add(s, 0, "seed")
		h.g.Seeds = append(h.g.Seeds, s.Value)
	}
	if len(h.queue) == 0 {
		return nil, fmt.Errorf("nothing to hunt from: no seeds given and the profile seed queries returned nothing")
	}

	for len(h.queue) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n := h.queue[0]
		h.queue = h.queue[1:]
		if n.Depth >= opts.Depth {
			continue
		}
		if len(h.g.Nodes) >= opts.MaxNodes {
			h.note(fmt.Sprintf("stopped expanding at %d nodes (-max-nodes)", opts.MaxNodes))
			break
		}
		h.expand(ctx, n)
	}

	// ASN and PTR are cheap DNS lookups and they decide whether an address
	// is a CDN edge, so every address gets them, not just the expanded ones.
	for _, n := range h.g.Sorted() {
		if n.Kind != ioc.IP || n.Meta["asn"] != "" {
			continue
		}
		if addr, err := netip.ParseAddr(n.Value); err == nil && ioc.Routable(addr) {
			h.enrichIP(ctx, n, addr)
		}
	}

	if opts.Active && h.Prober != nil {
		h.probeAll(ctx)
	}

	score.Compute(h.g, h.Profile, opts.Now)
	h.g.Finished = time.Now().UTC()
	return h.g, nil
}

func (h *Hunter) logf(format string, a ...any) { fmt.Fprintf(h.opts.Log, format+"\n", a...) }

func (h *Hunter) note(s string) {
	if !h.notes[s] {
		h.notes[s] = true
		h.g.Notes = append(h.g.Notes, s)
	}
}

// warn records a source failure without stopping the hunt. Offline cache
// misses are expected (the replay only holds what the original run asked
// for) and are summarised rather than listed.
func (h *Hunter) warn(src string, err error) {
	if errors.Is(err, source.ErrNotCached) {
		h.note(src + ": some lookups not in the offline cache")
		return
	}
	h.note(fmt.Sprintf("%s: %v", src, err))
}

func (h *Hunter) enqueue(n *graph.Node) { h.queue = append(h.queue, n) }

func (h *Hunter) add(i ioc.IOC, depth int, via string) *graph.Node {
	n, isNew := h.g.Add(i, depth, via)
	if isNew {
		h.enqueue(n)
		h.attach(n)
	}
	return n
}

// attach links a URL or ip:port to the things it's made of, without any
// lookups: http://1.2.3.4:1224/x is served by 1.2.3.4:1224, which is a port
// of 1.2.3.4. Done at creation so the structure exists at any depth.
func (h *Hunter) attach(n *graph.Node) {
	i := n.IOC()
	switch n.Kind {
	case ioc.URL:
		host, ok := i.Host()
		if !ok {
			return
		}
		u, _ := url.Parse(n.Value)
		if host.Kind == ioc.IP && u != nil && u.Port() != "" {
			pi, err := ioc.Parse(net.JoinHostPort(host.Value, u.Port()))
			if err == nil {
				pn := h.add(pi, n.Depth+1, "port of "+n.Value)
				h.g.Link(pn.ID, n.ID, "serves", "parsed", "")
				return
			}
		}
		hn := h.add(host, n.Depth+1, "host of "+n.Value)
		h.g.Link(hn.ID, n.ID, "hosts", "parsed", "")
	case ioc.IPPort:
		host, ok := i.Host()
		if !ok {
			return
		}
		hn := h.add(host, n.Depth+1, "host of "+n.Value)
		h.g.Link(hn.ID, n.ID, "port-of", "parsed", "")
	}
}

// ---------------------------------------------------------------------------
// seeding

func (h *Hunter) seedFromProfile(ctx context.Context) error {
	if h.ThreatFox == nil {
		h.note("ThreatFox not configured: profile seeding skipped")
		return nil
	}
	for _, f := range h.Profile.Families {
		recs, err := h.ThreatFox.Malware(ctx, f.ThreatFox, h.opts.Limit)
		if err != nil {
			h.warn("ThreatFox malwareinfo "+f.ThreatFox, err)
			continue
		}
		h.logf("seed: ThreatFox %s -> %d IOCs", f.ThreatFox, len(recs))
		h.g.Seeds = append(h.g.Seeds, "threatfox:malware:"+f.ThreatFox)
		for _, r := range recs {
			h.addThreatFox(r, 0, "seed: ThreatFox "+f.ThreatFox, true)
		}
	}
	for _, t := range h.Profile.Tags {
		recs, err := h.ThreatFox.Tag(ctx, t, h.opts.Limit)
		if err != nil {
			h.warn("ThreatFox taginfo "+t, err)
			continue
		}
		h.logf("seed: ThreatFox tag %s -> %d IOCs", t, len(recs))
		h.g.Seeds = append(h.g.Seeds, "threatfox:tag:"+t)
		for _, r := range recs {
			h.addThreatFox(r, 0, "seed: ThreatFox tag "+t, true)
		}
	}
	return nil
}

// addThreatFox turns a ThreatFox record into a node with evidence. Records
// outside -since are dropped when seeding (old campaigns) but kept when
// they turn up while pivoting, where they're context with a decayed weight.
func (h *Hunter) addThreatFox(r source.TFIOC, depth int, via string, seeding bool) *graph.Node {
	if seeding && !r.Seen().IsZero() && h.opts.Now.Sub(r.Seen()) > h.opts.Since {
		return nil
	}
	i, err := tfIOC(r)
	if err != nil {
		return nil
	}
	n := h.add(i, depth, via)
	n.Observe(r.FirstSeen)
	n.Observe(r.LastSeen)
	n.Malware = graph.AddUnique(n.Malware, r.Printable)
	for _, t := range r.Tags {
		n.Tags = graph.AddUnique(n.Tags, t)
	}
	seen := r.Seen()
	ev := graph.Evidence{
		Seen:   &seen,
		Source: fmt.Sprintf("ThreatFox #%s (%s)", r.ID, r.Reporter),
		Ref:    "https://threatfox.abuse.ch/ioc/" + r.ID + "/",
	}
	conf := float64(r.Confidence) / 100
	if conf < 0.25 {
		conf = 0.25
	}
	if f, ok := h.Profile.FamilyFor(r.Malware); ok {
		ev.Signal, ev.Strength = "threatfox_family", conf
		ev.Detail = fmt.Sprintf("%s %s, confidence %d", f.Name, r.ThreatType, r.Confidence)
		n.AddEvidence(ev)
	} else if m := h.Profile.MatchTags(r.Tags); len(m) > 0 {
		ev.Signal, ev.Strength = "threatfox_tag", conf
		ev.Detail = fmt.Sprintf("%s (%s) tagged %s", r.Printable, r.ThreatType, strings.Join(m, ", "))
		n.AddEvidence(ev)
	}
	return n
}

func tfIOC(r source.TFIOC) (ioc.IOC, error) {
	switch r.IOCType {
	case "ip:port", "domain", "url":
		return ioc.Parse(r.IOC)
	case "sha256_hash":
		return ioc.IOC{Kind: ioc.SHA256, Value: strings.ToLower(r.IOC)}, nil
	case "md5_hash":
		return ioc.IOC{Kind: ioc.MD5, Value: strings.ToLower(r.IOC)}, nil
	}
	return ioc.Parse(r.IOC)
}

// ---------------------------------------------------------------------------
// pivots

func (h *Hunter) expand(ctx context.Context, n *graph.Node) {
	next := n.Depth + 1

	switch n.Kind {
	case ioc.IP:
		addr, err := netip.ParseAddr(n.Value)
		if err != nil || !ioc.Routable(addr) {
			return
		}
		h.enrichIP(ctx, n, addr)
		h.urlhaus(ctx, n, next)
		h.threatfoxSearch(ctx, n, next)

	case ioc.Domain:
		if h.Profile.IsBenign(n.Value) {
			return
		}
		if _, shared := h.Profile.Shared(n.Value); shared {
			return
		}
		h.resolve(ctx, n, next)
		h.certs(ctx, n, next)
		h.urlhaus(ctx, n, next)
		h.threatfoxSearch(ctx, n, next)
	}
}

func (h *Hunter) enrichIP(ctx context.Context, n *graph.Node, addr netip.Addr) {
	if h.DNS == nil {
		return
	}
	if a, err := h.DNS.ASN(ctx, addr); err == nil && a.Number != "" {
		n.Meta["asn"], n.Meta["prefix"], n.Meta["country"] = a.Number, a.Prefix, a.Country
		if a.Name != "" {
			n.Meta["as_name"] = a.Name
		}
	} else if err != nil {
		h.warn("Team Cymru", err)
	}
	if ptr, err := h.DNS.PTR(ctx, addr); err == nil && len(ptr) > 0 {
		n.Meta["ptr"] = strings.Join(ptr, ",")
	}
}

func (h *Hunter) urlhaus(ctx context.Context, n *graph.Node, depth int) {
	if h.URLhaus == nil {
		return
	}
	urls, err := h.URLhaus.Host(ctx, n.Value)
	if err != nil {
		h.warn("URLhaus", err)
		return
	}
	for _, u := range urls {
		i, err := ioc.Parse(u.URL)
		if err != nil {
			continue
		}
		un := h.add(i, depth, "URLhaus host "+n.Value)
		h.g.Link(n.ID, un.ID, "hosts", "URLhaus", "")
		un.Observe(u.Added)
		un.Meta["urlhaus_status"] = u.Status
		for _, t := range u.Tags {
			un.Tags = graph.AddUnique(un.Tags, t)
		}
		added := u.Added
		ev := graph.Evidence{Strength: 1, Seen: &added, Source: "URLhaus (" + u.Reporter + ")", Ref: u.Reference}
		if m := h.Profile.MatchTags(u.Tags); len(m) > 0 {
			ev.Signal = "urlhaus_tag"
			ev.Detail = fmt.Sprintf("%s, tagged %s", u.Threat, strings.Join(m, ", "))
		} else {
			ev.Signal = "urlhaus_listed"
			ev.Detail = fmt.Sprintf("%s, tags %v", u.Threat, u.Tags)
		}
		un.AddEvidence(ev)
	}
}

func (h *Hunter) threatfoxSearch(ctx context.Context, n *graph.Node, depth int) {
	if h.ThreatFox == nil {
		return
	}
	recs, err := h.ThreatFox.Search(ctx, n.Value)
	if err != nil {
		h.warn("ThreatFox search", err)
		return
	}
	for _, r := range recs {
		if m := h.addThreatFox(r, depth, "ThreatFox search "+n.Value, false); m != nil && m.ID != n.ID {
			// An ip:port or URL found by searching an IP/domain hangs off it.
			if host, ok := m.IOC().Host(); ok && host.ID() == n.ID {
				rel := "hosts"
				if m.Kind == ioc.IPPort {
					rel = "port-of"
				}
				h.g.Link(n.ID, m.ID, rel, "ThreatFox", "")
			}
		}
	}
}

func (h *Hunter) resolve(ctx context.Context, n *graph.Node, depth int) {
	if h.DNS == nil {
		return
	}
	addrs, err := h.DNS.Addrs(ctx, n.Value)
	if err != nil {
		h.warn("DNS", err)
		return
	}
	for _, a := range addrs {
		an := h.add(ioc.IOC{Kind: ioc.IP, Value: a.String()}, depth, "DNS "+n.Value)
		h.g.Link(n.ID, an.ID, "resolves-to", "DNS", "")
	}
	if len(addrs) > 0 {
		n.Meta["resolved"] = fmt.Sprint(len(addrs)) + " address(es)"
	}
}

func (h *Hunter) certs(ctx context.Context, n *graph.Node, depth int) {
	if h.CrtSh == nil {
		return
	}
	certs, err := h.CrtSh.Certs(ctx, n.Value)
	if err != nil {
		h.warn("crt.sh", err)
		return
	}
	n.Meta["certificates"] = fmt.Sprint(len(certs))
	for _, c := range certs {
		if len(c.Names) > h.opts.MaxSANs {
			h.note(fmt.Sprintf("crt.sh: skipped certificate %d with %d names (shared hosting or SaaS)", c.ID, len(c.Names)))
			continue
		}
		for _, name := range c.Names {
			if name == n.Value || h.Profile.IsBenign(name) {
				continue
			}
			if _, shared := h.Profile.Shared(name); shared {
				continue
			}
			i, err := ioc.Parse(name)
			if err != nil || i.Kind != ioc.Domain {
				continue
			}
			sn := h.add(i, depth, "crt.sh cert "+fmt.Sprint(c.ID)+" with "+n.Value)
			sn.Observe(c.NotBefore)
			h.g.Link(n.ID, sn.ID, "shares-cert", fmt.Sprintf("crt.sh %d", c.ID),
				fmt.Sprintf("%d names on cert %d (%s, %s)", len(c.Names), c.ID, c.Issuer, c.NotBefore.Format("2006-01-02")))
		}
	}
}

// probeAll checks every ip:port (and URL with an explicit port) for a live
// Engine.IO server.
func (h *Hunter) probeAll(ctx context.Context) {
	for _, n := range h.g.Sorted() {
		if n.Kind != ioc.IPPort {
			continue
		}
		r := h.Prober.Check(ctx, n.Value)
		h.logf("probe %s: live=%v %s", n.Value, r.Live, r.Error)
		if !r.Live {
			continue
		}
		now := h.opts.Now
		n.Meta["engineio"] = fmt.Sprintf("EIO=%d upgrades=%v ping=%d/%d", r.EIO, r.Upgrades, r.PingInterval, r.PingTimeout)
		n.AddEvidence(graph.Evidence{Signal: "engineio_live", Strength: 1, Seen: &now, Source: "active probe",
			Detail: "answers an Engine.IO handshake (" + n.Meta["engineio"] + ")"})
	}
}
