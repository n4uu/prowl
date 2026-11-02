package score

import (
	"math"
	"testing"
	"time"

	"github.com/n4uu/prowl/internal/graph"
	"github.com/n4uu/prowl/internal/ioc"
	"github.com/n4uu/prowl/internal/profile"
)

func prof(t *testing.T) *profile.Profile {
	p, err := profile.Parse([]byte(`
name: t
scoring:
  prior: 0.02
  half_life_days: 100
  group_decay: 0.5
  evidence:
    strong: {lr: 100, group: a}
    weak:   {lr: 4,   group: b}
    neg:    {lr: 0.1, group: c}
`))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func logit(p float64) float64 { return math.Log(p / (1 - p)) }

func TestCombine(t *testing.T) {
	p := prof(t)
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	prior := logit(0.02)

	pr, _ := combine(nil, p, now)
	if math.Abs(pr-0.02) > 1e-9 {
		t.Errorf("no evidence: %v", pr)
	}

	one, _ := combine([]graph.Evidence{{Signal: "strong", Strength: 1}}, p, now)
	if math.Abs(logit(one)-(prior+math.Log(100))) > 1e-9 {
		t.Errorf("single strong: %v", one)
	}

	// Same group: the second counts half.
	two, _ := combine([]graph.Evidence{{Signal: "strong", Strength: 1}, {Signal: "strong", Strength: 1, Source: "b"}}, p, now)
	if math.Abs(logit(two)-(prior+1.5*math.Log(100))) > 1e-9 {
		t.Errorf("group damping: %v", logit(two)-prior)
	}

	// Different groups add in full.
	mixed, _ := combine([]graph.Evidence{{Signal: "strong", Strength: 1}, {Signal: "weak", Strength: 1}}, p, now)
	if math.Abs(logit(mixed)-(prior+math.Log(100)+math.Log(4))) > 1e-9 {
		t.Errorf("independent groups: %v", logit(mixed)-prior)
	}

	// Half strength is half the weight of evidence.
	half, _ := combine([]graph.Evidence{{Signal: "strong", Strength: 0.5}}, p, now)
	if math.Abs(logit(half)-(prior+0.5*math.Log(100))) > 1e-9 {
		t.Errorf("strength: %v", logit(half)-prior)
	}

	// One half-life old: half the weight.
	old := now.AddDate(0, 0, -100)
	aged, _ := combine([]graph.Evidence{{Signal: "strong", Strength: 1, Seen: &old}}, p, now)
	if math.Abs(logit(aged)-(prior+0.5*math.Log(100))) > 1e-6 {
		t.Errorf("decay: %v", logit(aged)-prior)
	}

	// Negative evidence isn't decayed or damped and pulls down.
	neg, reasons := combine([]graph.Evidence{{Signal: "strong", Strength: 1}, {Signal: "neg", Strength: 1, Seen: &old}}, p, now)
	if math.Abs(logit(neg)-(prior+math.Log(100)+math.Log(0.1))) > 1e-9 {
		t.Errorf("negative: %v", logit(neg)-prior)
	}
	if reasons[0].Signal != "strong" {
		t.Errorf("reasons not sorted by impact: %+v", reasons)
	}

	// Unknown signals are ignored rather than crashing a hunt.
	unk, _ := combine([]graph.Evidence{{Signal: "nope", Strength: 1}}, p, now)
	if unk != pr {
		t.Errorf("unknown signal changed the score")
	}
}

func TestTiers(t *testing.T) {
	for p, want := range map[float64]string{0.999: "almost-certain", 0.95: "almost-certain", 0.9: "very-likely", 0.6: "likely", 0.5: "roughly-even-chance", 0.3: "unlikely", 0.1: "very-unlikely", 0.01: "almost-no-chance"} {
		if got := Tier(p); got != want {
			t.Errorf("Tier(%v) = %s, want %s", p, got, want)
		}
	}
	if TierRank("likely") <= TierRank("unlikely") || TierRank("bogus") != -1 {
		t.Error("TierRank ordering")
	}
}

// ThreatFox has the front page of a block explorer filed under this
// campaign (EtherHiding reads the next stage from chain). Exporting it would
// block the whole service; a deep URL on the same service stays.
func TestBenignFrontPage(t *testing.T) {
	p, err := profile.Load("contagious-interview")
	if err != nil {
		t.Fatal(err)
	}
	g := graph.New(p.Name)
	root, _ := g.Add(ioc.MustParse("https://tronscan.org/"), 0, "seed")
	deep, _ := g.Add(ioc.MustParse("https://github.com/attacker-example/tasks/raw/main/run.sh"), 0, "seed")
	for _, n := range []*graph.Node{root, deep} {
		n.Exportable = true
		structural(n, p)
	}
	if root.Exportable || root.NoExport != "front page of a benign service" {
		t.Errorf("tronscan.org/ exportable=%v (%q)", root.Exportable, root.NoExport)
	}
	if !deep.Exportable {
		t.Errorf("deep URL on github.com dropped: %q", deep.NoExport)
	}
}
