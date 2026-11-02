// Command prowl hunts a campaign's C2 infrastructure from public telemetry:
// it seeds from ThreatFox, pivots through URLhaus, certificate transparency,
// DNS and ASN data, scores every indicator with explainable evidence, and
// exports MISP and STIX.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/n4uu/prowl/internal/demo"
	"github.com/n4uu/prowl/internal/export"
	"github.com/n4uu/prowl/internal/graph"
	"github.com/n4uu/prowl/internal/hunt"
	"github.com/n4uu/prowl/internal/ioc"
	"github.com/n4uu/prowl/internal/probe"
	"github.com/n4uu/prowl/internal/profile"
	"github.com/n4uu/prowl/internal/score"
	"github.com/n4uu/prowl/internal/source"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var err error
	switch os.Args[1] {
	case "hunt":
		err = runHunt(ctx, os.Args[2:], false)
	case "demo":
		err = runHunt(ctx, os.Args[2:], true)
	case "explain":
		err = runExplain(os.Args[2:])
	case "export":
		err = runExport(os.Args[2:])
	case "probe":
		err = runProbe(ctx, os.Args[2:])
	case "profile":
		err = runProfile(os.Args[2:])
	case "version", "-version", "--version":
		fmt.Printf("prowl %s\n", version)
		return
	case "help", "-h", "-help", "--help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "prowl: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `prowl: campaign infrastructure hunting from public telemetry

usage:
  prowl hunt [flags] [indicator...]      seed from the profile (and/or indicators), pivot, score, export
  prowl demo [flags]                     the same hunt against a built-in synthetic dataset, offline
  prowl explain [-in hunt.json] <ioc>    full scoring breakdown for one indicator
  prowl export -format <fmt> [flags]     re-export a saved hunt: misp, stix, csv, dot, text
  prowl probe <ip:port>...               actively check for a live Engine.IO server (touches the target)
  prowl profile [name|file.yaml]         print a builtin profile, or validate your own
  prowl version

ThreatFox and URLhaus need an abuse.ch Auth-Key in ABUSECH_AUTH_KEY
(free at https://auth.abuse.ch/). crt.sh, DNS and Team Cymru need nothing.
`)
}

type huntFlags struct {
	profile, seeds, cache, out, since, min, ids, tlp, producer string
	depth, maxNodes, limit                                     int
	offline, noSeed, noDNS, active, verbose, quiet             bool
	ttl                                                        time.Duration
}

func runHunt(ctx context.Context, args []string, isDemo bool) error {
	name := "hunt"
	if isDemo {
		name = "demo"
	}
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	var f huntFlags
	fs.StringVar(&f.profile, "profile", "contagious-interview", "builtin profile name or path to a profile YAML")
	fs.StringVar(&f.seeds, "seeds", "", "file of seed indicators, one per line (defanged is fine)")
	fs.BoolVar(&f.noSeed, "no-seed", false, "don't query the profile's families and tags; pivot from the given indicators only")
	fs.IntVar(&f.depth, "depth", 2, "pivot hops from a seed")
	fs.IntVar(&f.maxNodes, "max-nodes", 400, "stop expanding once pivoting has added this many nodes beyond the seeds")
	fs.IntVar(&f.limit, "limit", 1000, "records per ThreatFox seed query")
	fs.StringVar(&f.since, "since", "365d", "drop ThreatFox seed records not seen within this window (e.g. 90d, 2160h)")
	fs.StringVar(&f.cache, "cache", defaultCache(), "response cache directory (\"\" to disable)")
	fs.DurationVar(&f.ttl, "ttl", 0, "treat cache entries older than this as missing (0 = never expire)")
	fs.BoolVar(&f.offline, "offline", false, "use only the cache; no network at all")
	fs.BoolVar(&f.noDNS, "no-dns", false, "skip DNS, PTR and Team Cymru lookups (resolving a suspect domain can reach a name server the operator runs)")
	fs.BoolVar(&f.active, "active", false, "probe ip:port indicators for a live Engine.IO server (sends traffic to the suspected C2)")
	fs.StringVar(&f.out, "out", "prowl-out", "directory for hunt.json, indicators.csv, misp-event.json, stix-bundle.json, graph.dot")
	fs.StringVar(&f.min, "min", "likely", "lowest tier exported")
	fs.StringVar(&f.ids, "ids", "very-likely", "lowest tier flagged for detection (MISP to_ids)")
	fs.StringVar(&f.tlp, "tlp", "amber", "TLP for exports: clear, green, amber, amber+strict, red")
	fs.StringVar(&f.producer, "producer", "prowl", "producer name for the STIX identity")
	fs.BoolVar(&f.verbose, "v", false, "log each seed query and probe")
	fs.BoolVar(&f.quiet, "q", false, "don't print the summary")
	fs.Parse(args)

	p, err := profile.Load(f.profile)
	if err != nil {
		return err
	}
	since, err := parseDays(f.since)
	if err != nil {
		return fmt.Errorf("-since: %w", err)
	}
	if score.TierRank(f.min) < 0 || score.TierRank(f.ids) < 0 {
		return fmt.Errorf("unknown tier; use one of almost-no-chance, very-unlikely, unlikely, roughly-even-chance, likely, very-likely, almost-certain")
	}

	var seeds []ioc.IOC
	for _, a := range fs.Args() {
		i, err := ioc.Parse(a)
		if err != nil {
			return err
		}
		seeds = append(seeds, i)
	}
	if f.seeds != "" {
		more, err := readSeeds(f.seeds)
		if err != nil {
			return err
		}
		seeds = append(seeds, more...)
	}

	var cache source.Cache
	if f.cache != "" && !isDemo {
		cache = &source.DirCache{Dir: f.cache, TTL: f.ttl}
	}
	if isDemo {
		cache = source.NewMemCache()
	}
	client := source.NewClient(cache, f.offline && !isDemo)
	dns := source.NewDNS(cache, f.offline && !isDemo)
	key := os.Getenv("ABUSECH_AUTH_KEY")
	now := time.Now().UTC()

	if isDemo {
		d := demo.New(now)
		client.HTTP = &http.Client{Transport: d.Transport()}
		client.MinInterval = nil
		dns.R = d.Resolver()
		key = "demo"
		fmt.Fprintln(os.Stderr, "demo: synthetic dataset (RFC 5737 addresses, .example domains); nothing leaves this process")
	}

	h := &hunt.Hunter{
		Profile: p,
		CrtSh:   &source.CrtSh{C: client},
		DNS:     dns,
	}
	if f.noDNS {
		if isDemo {
			return fmt.Errorf("-no-dns makes no sense against the synthetic dataset")
		}
		h.DNS = nil
		fmt.Fprintln(os.Stderr, "prowl: -no-dns: no resolution, no ASN or CDN check; CDN addresses can only be caught by the profile's own lists")
	}
	if key != "" || f.offline {
		h.ThreatFox = &source.ThreatFox{C: client, Key: key}
		h.URLhaus = &source.URLhaus{C: client, Key: key}
	} else {
		fmt.Fprintln(os.Stderr, "prowl: ABUSECH_AUTH_KEY not set; ThreatFox and URLhaus are off, so profile seeding is too")
	}
	if f.active {
		if isDemo {
			return fmt.Errorf("-active makes no sense against the synthetic dataset")
		}
		fmt.Fprintln(os.Stderr, "prowl: -active sends HTTP requests to suspected C2 servers from this machine's address")
		h.Prober = probe.New()
	}

	opts := hunt.Options{
		Depth: f.depth, MaxNodes: f.maxNodes, Since: since, Limit: f.limit,
		NoSeed: f.noSeed, Active: f.active, Now: now,
	}
	if f.verbose {
		opts.Log = os.Stderr
	}
	g, err := h.Run(ctx, seeds, opts)
	if err != nil {
		return err
	}
	g.Stats = map[string]any{"sources": client.Stats()}

	eo := export.Options{MinTier: f.min, IDSTier: f.ids, TLP: f.tlp, Producer: f.producer, Now: now}
	if err := writeAll(f.out, g, p, eo); err != nil {
		return err
	}
	if !f.quiet {
		export.Text(os.Stdout, g, eo)
		fmt.Printf("\nwrote %s/{hunt.json,indicators.csv,misp-event.json,stix-bundle.json,graph.dot}\n", f.out)
	}
	return nil
}

func defaultCache() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "prowl")
}

// parseDays accepts Go durations plus a "d" suffix for days.
func parseDays(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, err
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

func readSeeds(path string) ([]ioc.IOC, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []ioc.IOC
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		i, err := ioc.Parse(s)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, line, err)
		}
		out = append(out, i)
	}
	return out, sc.Err()
}

func writeAll(dir string, g *graph.Graph, p *profile.Profile, eo export.Options) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	files := []struct {
		name string
		fn   func(io.Writer) error
	}{
		{"hunt.json", g.Save},
		{"indicators.csv", func(w io.Writer) error { return export.CSV(w, g, eo) }},
		{"misp-event.json", func(w io.Writer) error { return export.MISP(w, g, p, eo) }},
		{"stix-bundle.json", func(w io.Writer) error { return export.STIX(w, g, p, eo) }},
		{"graph.dot", func(w io.Writer) error { return export.DOT(w, g, eo) }},
	}
	for _, f := range files {
		out, err := os.Create(filepath.Join(dir, f.name))
		if err != nil {
			return err
		}
		if err := f.fn(out); err != nil {
			out.Close()
			return fmt.Errorf("%s: %w", f.name, err)
		}
		if err := out.Close(); err != nil {
			return err
		}
	}
	return nil
}

func loadHunt(path string) (*graph.Graph, *profile.Profile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	g, err := graph.Load(f)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	p, err := profile.Load(g.Profile)
	if err != nil {
		return nil, nil, err
	}
	return g, p, nil
}

func runExplain(args []string) error {
	fs := flag.NewFlagSet("explain", flag.ExitOnError)
	in := fs.String("in", "prowl-out/hunt.json", "saved hunt")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: prowl explain [-in hunt.json] <indicator>")
	}
	g, p, err := loadHunt(*in)
	if err != nil {
		return err
	}
	want, err := ioc.Parse(fs.Arg(0))
	if err != nil {
		return err
	}
	n := g.Nodes[want.ID()]
	if n == nil {
		// Let "1.2.3.4" find "1.2.3.4:1418" and friends.
		for _, m := range g.Sorted() {
			if strings.Contains(m.Value, want.Value) {
				n = m
				break
			}
		}
	}
	if n == nil {
		return fmt.Errorf("%s is not in %s", want.Value, *in)
	}
	export.Explain(os.Stdout, g, n, p)
	return nil
}

func runExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	in := fs.String("in", "prowl-out/hunt.json", "saved hunt")
	format := fs.String("format", "text", "misp, stix, csv, dot or text")
	min := fs.String("min", "likely", "lowest tier exported")
	ids := fs.String("ids", "very-likely", "lowest tier flagged for detection")
	tlp := fs.String("tlp", "amber", "TLP")
	producer := fs.String("producer", "prowl", "STIX identity name")
	fs.Parse(args)
	g, p, err := loadHunt(*in)
	if err != nil {
		return err
	}
	eo := export.Options{MinTier: *min, IDSTier: *ids, TLP: *tlp, Producer: *producer, Now: g.Started}
	switch *format {
	case "misp":
		return export.MISP(os.Stdout, g, p, eo)
	case "stix":
		return export.STIX(os.Stdout, g, p, eo)
	case "csv":
		return export.CSV(os.Stdout, g, eo)
	case "dot":
		return export.DOT(os.Stdout, g, eo)
	case "text":
		export.Text(os.Stdout, g, eo)
		return nil
	}
	return fmt.Errorf("unknown format %q", *format)
}

func runProbe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "JSON output")
	fs.Parse(args)
	if fs.NArg() == 0 {
		return fmt.Errorf("usage: prowl probe <ip:port>...")
	}
	fmt.Fprintln(os.Stderr, "prowl: probing sends an Engine.IO handshake to each target from this machine's address")
	p := probe.New()
	var results []probe.Result
	for _, a := range fs.Args() {
		i, err := ioc.Parse(a)
		if err != nil || (i.Kind != ioc.IPPort && i.Kind != ioc.Domain) {
			return fmt.Errorf("%s: want ip:port or host:port", a)
		}
		target := i.Value
		if i.Kind == ioc.Domain {
			target = ioc.Refang(a)
		}
		results = append(results, p.Check(ctx, target))
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	}
	for _, r := range results {
		switch {
		case r.Live:
			fmt.Printf("%-24s live  EIO=%d sid=%s upgrades=%v ping=%d/%d server=%q powered-by=%q\n",
				r.Target, r.EIO, r.SID, r.Upgrades, r.PingInterval, r.PingTimeout, r.Server, r.PoweredBy)
		case r.Error != "":
			fmt.Printf("%-24s error %s\n", r.Target, r.Error)
		default:
			fmt.Printf("%-24s no Engine.IO handshake (HTTP %d)\n", r.Target, r.Status)
		}
	}
	return nil
}

func runProfile(args []string) error {
	if len(args) == 0 {
		fmt.Println("builtin profiles:", strings.Join(profile.Builtin(), ", "))
		return nil
	}
	arg := args[0]
	if raw, err := profile.Raw(arg); err == nil {
		os.Stdout.Write(raw)
		return nil
	}
	p, err := profile.Load(arg)
	if err != nil {
		return err
	}
	if len(p.Families) == 0 && len(p.Tags) == 0 {
		return errors.New("profile has no families or tags: nothing to seed from (hunts will need explicit indicators)")
	}
	fmt.Printf("%s: ok (%d families, %d tags, %d ports, %d paths, %d evidence weights)\n",
		p.Name, len(p.Families), len(p.Tags), len(p.Ports), len(p.Paths), len(p.Scoring.Evidence))
	return nil
}
