// Package profile loads campaign profiles: the data that tells prowl what
// to seed from, what's characteristic, and how much each signal is worth.
package profile

import (
	"embed"
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed builtin/*.yaml
var builtin embed.FS

// Profile is a campaign definition.
type Profile struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Actor       struct {
		Name    string   `yaml:"name"`
		Aliases []string `yaml:"aliases"`
	} `yaml:"actor"`
	Families      []Family          `yaml:"families"`
	Tags          []string          `yaml:"tags"`
	Ports         map[int]string    `yaml:"ports"`
	Paths         map[string]string `yaml:"paths"`
	SharedHosting []string          `yaml:"shared_hosting"`
	SharedASNs    map[string]string `yaml:"shared_asns"`
	Benign        []string          `yaml:"benign"`
	Scoring       Scoring           `yaml:"scoring"`
}

// Family is a malware family as named on ThreatFox and Malpedia.
type Family struct {
	Name      string `yaml:"name"`
	ThreatFox string `yaml:"threatfox"`
	Malpedia  string `yaml:"malpedia"`
}

// Scoring holds the evidence weights.
type Scoring struct {
	Prior        float64             `yaml:"prior"`
	HalfLifeDays float64             `yaml:"half_life_days"`
	GroupDecay   float64             `yaml:"group_decay"`
	Evidence     map[string]Evidence `yaml:"evidence"`
}

// Evidence is one signal's likelihood ratio and correlation group.
type Evidence struct {
	LR    float64 `yaml:"lr"`
	Group string  `yaml:"group"`
}

// Builtin lists the profiles compiled into the binary.
func Builtin() []string {
	ents, _ := builtin.ReadDir("builtin")
	var out []string
	for _, e := range ents {
		out = append(out, strings.TrimSuffix(e.Name(), ".yaml"))
	}
	sort.Strings(out)
	return out
}

// Load returns a builtin profile by name, or reads one from a file path.
func Load(nameOrPath string) (*Profile, error) {
	var raw []byte
	var err error
	if strings.ContainsAny(nameOrPath, `/\`) || strings.HasSuffix(nameOrPath, ".yaml") || strings.HasSuffix(nameOrPath, ".yml") {
		raw, err = os.ReadFile(nameOrPath)
	} else {
		raw, err = builtin.ReadFile("builtin/" + nameOrPath + ".yaml")
		if err != nil {
			return nil, fmt.Errorf("no builtin profile %q (have %s)", nameOrPath, strings.Join(Builtin(), ", "))
		}
	}
	if err != nil {
		return nil, err
	}
	return Parse(raw)
}

// Raw returns the YAML source of a builtin profile.
func Raw(name string) ([]byte, error) {
	return builtin.ReadFile("builtin/" + name + ".yaml")
}

// Parse decodes and validates a profile.
func Parse(raw []byte) (*Profile, error) {
	var p Profile
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("profile: %w", err)
	}
	if p.Name == "" {
		return nil, fmt.Errorf("profile: missing name")
	}
	s := &p.Scoring
	if s.Prior <= 0 || s.Prior >= 1 {
		return nil, fmt.Errorf("profile %s: scoring.prior must be in (0,1)", p.Name)
	}
	if s.HalfLifeDays <= 0 {
		s.HalfLifeDays = 120
	}
	if s.GroupDecay <= 0 || s.GroupDecay > 1 {
		s.GroupDecay = 0.5
	}
	for name, e := range s.Evidence {
		if e.LR <= 0 {
			return nil, fmt.Errorf("profile %s: evidence %s needs lr > 0", p.Name, name)
		}
		if e.Group == "" {
			return nil, fmt.Errorf("profile %s: evidence %s needs a group", p.Name, name)
		}
	}
	return &p, nil
}

// FamilyFor maps a ThreatFox malware name to a profile family.
func (p *Profile) FamilyFor(threatfox string) (Family, bool) {
	for _, f := range p.Families {
		if strings.EqualFold(f.ThreatFox, threatfox) {
			return f, true
		}
	}
	return Family{}, false
}

func normTag(t string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '-', '_', '.':
			return -1
		}
		return r
	}, strings.ToLower(t))
}

// MatchTags returns the campaign tags present in tags.
func (p *Profile) MatchTags(tags []string) []string {
	want := map[string]string{}
	for _, t := range p.Tags {
		// The first spelling is canonical; later ones only exist so
		// seeding can query ThreatFox's exact-match taginfo.
		if _, ok := want[normTag(t)]; !ok {
			want[normTag(t)] = t
		}
	}
	var out []string
	seen := map[string]bool{}
	for _, t := range tags {
		if canon, ok := want[normTag(t)]; ok && !seen[canon] {
			seen[canon] = true
			out = append(out, canon)
		}
	}
	return out
}

// PathMatch returns the longest profile path that path equals or sits
// under ("/pdown" matches "/pdown" and "/pdown/x", not "/pdownload").
func (p *Profile) PathMatch(path string) (string, string, bool) {
	best := ""
	for pp := range p.Paths {
		base := strings.TrimSuffix(pp, "/")
		if (path == base || path == pp || strings.HasPrefix(path, base+"/")) && len(pp) > len(best) {
			best = pp
		}
	}
	if best == "" {
		return "", "", false
	}
	return best, p.Paths[best], true
}

func suffixIn(domain string, list []string) (string, bool) {
	d := strings.ToLower(domain)
	for _, s := range list {
		s = strings.ToLower(strings.TrimPrefix(s, "."))
		if d == s || strings.HasSuffix(d, "."+s) {
			return s, true
		}
	}
	return "", false
}

// Shared reports whether a domain is on shared hosting.
func (p *Profile) Shared(domain string) (string, bool) { return suffixIn(domain, p.SharedHosting) }

// IsBenign reports whether a domain is a known-good service.
func (p *Profile) IsBenign(domain string) bool {
	_, ok := suffixIn(domain, p.Benign)
	return ok
}
