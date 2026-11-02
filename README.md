# prowl

[![ci](https://github.com/n4uu/prowl/actions/workflows/ci.yml/badge.svg)](https://github.com/n4uu/prowl/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/n4uu/prowl.svg)](https://pkg.go.dev/github.com/n4uu/prowl)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Hunts Contagious Interview C2 infrastructure from public telemetry.**
prowl seeds from what ThreatFox already knows about BeaverTail,
InvisibleFerret and OtterCookie, pivots through URLhaus, certificate
transparency, DNS and ASN data, puts a probability on every indicator it
reaches with the evidence behind it, and exports MISP and STIX 2.1.

The campaign itself (ports, URL paths, families, tags, shared hosting to
stay away from, evidence weights) is a YAML profile, not code. Hunting
something else is a matter of writing another one.

## Try it without a key

`prowl demo` runs the full pipeline against a built-in synthetic dataset:
fake ThreatFox, URLhaus and crt.sh answers served from inside the process,
a fake resolver for DNS and Team Cymru. Every address is from the RFC 5737
documentation ranges and every domain ends in `.example`; none of it is
real infrastructure. It exists to show what a hunt produces and to give the
tests something to assert on.

```
$ prowl demo
profile contagious-interview, 2026-11-02 08:13 UTC
25 nodes, 23 edges; 18 indicators at likely or above, 14 at very-likely or above

p     tier            type     indicator                                      last seen  why
>.99  almost-certain  ip:port  198.51.100[.]88:1224                           2026-10-23 threatfox_family: BeaverTail botnet_cc, confidence 100
>.99  almost-certain  url      hxxp://198.51.100[.]88:1224/pdown              2026-10-03 same_host: served by 198.51.100.88:1224 (base p=0.98)
>.99  almost-certain  url      hxxp://203.0.113[.]47:1224/uploads             2026-10-24 same_host: served by 203.0.113.47:1224 (base p=0.86)
>.99  almost-certain  ip:port  203.0.113[.]47:1224                            2026-10-08 same_host: serves http://203.0.113.47:1224/uploads (base p=0.98)
>.99  almost-certain  url      hxxp://203.0.113[.]47:1418/socket.io/?EIO=4... 2026-10-28 same_host: served by 203.0.113.47:1418 (base p=0.98)
>.99  almost-certain  url      hxxp://198.51.100[.]88:1224/keys               2026-10-03 same_host: served by 198.51.100.88:1224 (base p=0.98)
0.99  almost-certain  ip       203.0.113[.]47                                            same_host: same host as 203.0.113.47:1418 (base p=0.98)
0.98  almost-certain  ip:port  203.0.113[.]47:1418                            2026-10-30 threatfox_family: OtterCookie botnet_cc, confidence 100
0.96  almost-certain  ip       198.51.100[.]88                                           same_host: same host as 198.51.100.88:1224 (base p=0.98)
0.91  very-likely     sha256   5c1f0f8f4b2f6d3a9e7c0b1a2d3e4f5061728394a5b... 2026-10-21 threatfox_family: OtterCookie payload, confidence 100
0.91  very-likely     url      hxxps://assets-loader.vercel[.]app/api/ipcheck 2026-10-21 threatfox_family: OtterCookie payload_delivery, confidence 100
0.87  very-likely     ip:port  203.0.113[.]48:1418                            2026-10-12 threatfox_family: OtterCookie botnet_cc, confidence 75
0.85  very-likely     domain   api.nodecheck-cdn[.]example                    2026-10-03 threatfox_family: OtterCookie botnet_cc, confidence 100
0.84  very-likely     ip       203.0.113[.]48                                            same_host: same host as 203.0.113.48:1418 (base p=0.87)
0.72  likely          domain   cdn.nodecheck-cdn[.]example                    2026-09-30 shares_cert: shares a certificate with api.nodecheck-cdn.example (base p=0.85), 3 names...
0.72  likely          domain   metrics.devhire-portal[.]example               2026-10-02 shares_cert: shares a certificate with api.nodecheck-cdn.example (base p=0.85), 2 names...
0.72  likely          domain   nodecheck-cdn[.]example                        2026-09-30 shares_cert: shares a certificate with api.nodecheck-cdn.example (base p=0.85), 3 names...
0.69  likely          ip       203.0.113[.]49                                            resolves_to: address of api.nodecheck-cdn.example (base p=0.85)

seen but not exported
  domain   assets-loader.vercel[.]app               shared hosting (vercel.app)
  ip       192.0.2[.]80                             CDN address (AS13335 Cloudflare)
  domain   github[.]com                             benign service

notes
  crt.sh: skipped certificate 7000003 with 61 names (shared hosting or SaaS)

wrote prowl-out/{hunt.json,indicators.csv,misp-event.json,stix-bundle.json,graph.dot}
```

A few things in there are the point of the tool rather than incidental:

- Half the list was never reported anywhere. The `/keys` URL, the bare
  addresses, the three certificate siblings and `203.0.113.49` all came
  from pivoting, and each says which neighbour vouched for it.
- `assets-loader.vercel.app` is on the "not exported" list while the URL on
  it is `very-likely`. Blocking a vercel.app subdomain is fine; pivoting
  through it (crt.sh, DNS) would pull in a slice of Vercel's customers, so
  prowl doesn't.
- `cdn.nodecheck-cdn.example` shares a certificate with the C2 domain and
  is flagged, but the address it resolves to is a Cloudflare edge and is
  neither scored nor exported. Naive "domain resolves to IP, IP is now bad"
  pivoting is how blocklists end up with CDN ranges in them.
- A 61-name certificate was skipped. One cert covering two or three names is
  one operator; one covering sixty is a hosting panel.
- `198.51.100.89:1244` isn't there: it's a confidence-50 report from 300
  days ago and has decayed to `very-unlikely`. `198.51.100.90:1244`, 500
  days old, was never seeded at all (`-since 365d`).

## Why a node got its score

```
$ prowl explain 203.0.113.49
203.0.113.49  ip
p=0.692 (likely), base p=0.020 from its own evidence
found at depth 1: DNS api.nodecheck-cdn.example
meta as_name=EXAMPLE-VPS-AS Example VPS B.V., NL  asn=64500  country=NL  prefix=203.0.113.0/24

   -3.89  prior (p=0.02)
   +4.26  resolves_to      [infrastructure] LR 70.5   address of api.nodecheck-cdn.example (base p=0.85)
                                           DNS
   +0.35  same_prefix      [infrastructure] LR 2      203.0.113.0/24 also holds [203.0.113.47 203.0.113.48]
                                           graph
   +0.10  asn_cluster      [infrastructure] LR 1.5    AS64500 hosts 2 other likely nodes in this hunt
                                           Team Cymru
  ------
   +0.81  log-odds  ->  p=0.692

neighbours
  resolves-to  api.nodecheck-cdn.example                p=0.85  (DNS)
  resolves-to  nodecheck-cdn.example                    p=0.72  (DNS)
```

Every number in a score can be traced like this, down to the ThreatFox
record id or crt.sh certificate it came from. The same top reasons go into
the MISP attribute comment, the STIX indicator description and the CSV, so
whoever receives the export can see why something is on it.

## Scoring

Each node starts from a prior (the chance that an arbitrary host prowl
pivots to belongs to the campaign, 2% by default) and each piece of evidence
adds `strength * ln(LR)` to the log-odds. The likelihood ratios live in the
profile with a comment explaining them, so they can be argued with. Three
details keep the arithmetic honest:

**Correlated evidence is damped.** Naive Bayes assumes independence, and
threat intel evidence isn't: two ThreatFox reports of one IOC usually mean
one reporter copied another, and ThreatFox and URLhaus share a community.
Every signal belongs to a group; within a group the strongest counts in
full, the second at half, the third at a quarter.

**Sightings decay.** C2 addresses churn within weeks. Dated evidence loses
half its weight every `half_life_days` (120 by default). Structural
evidence, like a port or a path, doesn't.

**Association uses base scores.** "Same host as", "resolves to", "shares a
certificate with" are computed from the neighbour's *base* probability, the
score from its own direct evidence only, and only from neighbours at 0.5 or
above. Using final scores would let two weak nodes talk each other up in a
loop. Certificate evidence is diluted past five names on the cert.

Tiers use the estimative language of ICD 203, which is also MISP's
`estimative-language` taxonomy: almost-certain (95%+), very-likely (80%+),
likely (55%+), roughly-even-chance, unlikely, very-unlikely,
almost-no-chance. By default `likely` and up are exported and `very-likely`
and up get `to_ids`.

## Pivots

| From | Through | To |
| --- | --- | --- |
| profile family / tag | ThreatFox `malwareinfo`, `taginfo` | seed IOCs with evidence |
| URL, ip:port | parsing (no lookup) | the ip:port that serves it, the address |
| address | URLhaus `host`, ThreatFox `search_ioc` | URLs on it, other ports |
| address | Team Cymru (DNS) | ASN, prefix, AS name; CDN check |
| domain | DNS | addresses |
| domain | crt.sh | names sharing a certificate |
| domain | URLhaus, ThreatFox | URLs, other reports |

Shared hosting and benign services are never pivoted through. Depth (2) and
node count (400) are capped. ASN lookups run for every address, including
ones past the depth limit, since that's what decides whether an address is
a CDN edge.

`-active` adds one more: an Engine.IO handshake (`GET
/socket.io/?EIO=4&transport=polling`, falling back to EIO=3) against every
ip:port, which confirms a live socket.io server, the OtterCookie shell
transport. That request goes to the suspected C2 from your address, so it's
off by default; send it through infrastructure you've checked (see
[wireguardian](https://github.com/n4uu/wireguardian)). `prowl probe
ip:port` does the same for a single target.

## Reproducible hunts

Every response, HTTP and DNS alike, is cached on disk under its request
(the Auth-Key header is never part of the key or the stored record).
`-offline` runs from the cache only. Run a hunt once with network access and
the exact same graph can be rebuilt next month for a report, or with a
tweaked profile, without touching the APIs again and without the answers
having changed underneath you. `-ttl` expires entries when you do want fresh
data.

## Install & use

```sh
git clone https://github.com/n4uu/prowl
cd prowl
make build
export ABUSECH_AUTH_KEY=...                      # free: https://auth.abuse.ch/
./bin/prowl hunt                                 # seed from the profile, depth 2
./bin/prowl hunt -no-seed -depth 3 api.c2.example 203.0.113.9:1418   # start from your own IOCs
./bin/prowl hunt -seeds iocs.txt                 # one per line, defanged is fine
./bin/prowl explain 203.0.113.9
./bin/prowl export -format stix -tlp green > bundle.json
./bin/prowl profile contagious-interview > my-profile.yaml   # copy and edit
./bin/prowl hunt -profile my-profile.yaml
```

Without a key, ThreatFox and URLhaus are skipped and so is profile seeding;
crt.sh, DNS and Team Cymru still work from indicators you give it.

Output, in `-out` (default `prowl-out/`):

| File | What |
| --- | --- |
| `hunt.json` | the whole graph: nodes, edges, evidence, scores, source stats. `explain` and `export` read it |
| `indicators.csv` | one row per exported indicator with its top three reasons |
| `misp-event.json` | a MISP event for `/events/add` or the import UI. `ip-dst\|port`, `domain`, `url`, `sha256` attributes with first/last seen, `to_ids` by tier, an `estimative-language` tag each, TLP at event level. Attribute UUIDs are derived from the indicator, so importing a later hunt updates instead of duplicating |
| `stix-bundle.json` | STIX 2.1: identity, intrusion set with aliases, one malware SDO per family, and per indicator an indicator SDO (`confidence` = probability), an infrastructure SDO and the observables. SCO ids use the spec's deterministic UUIDv5 scheme, so the same address has the same id no matter who produced it |
| `graph.dot` | `dot -Tsvg graph.dot > graph.svg`, coloured by tier |

## Testing

```sh
make test               # unit tests and a full hunt against the synthetic dataset
make validate-exports   # demo hunt, then STIX/MISP checked with stix2 + pymisp
```

The source parsers are tested against `httptest` servers speaking each
API's real response shapes, including the awkward bits: ThreatFox returns
`"data": "Your search did not yield any results"` (a string where an array
should be), and crt.sh lists precertificate and leaf separately. One test greps the cache directory for the Auth-Key
to make sure it never lands on disk. The export tests check the STIX
observable ids against values produced by the OASIS `stix2` library, and CI
validates the demo's bundle and event with `stix2`, `stix2-patterns` and
`pymisp`.

## Limitations

- **Coverage is whatever the community reported.** ThreatFox and URLhaus
  are crowd-sourced; a family nobody has filed under the right name won't
  seed. The tag list in the profile catches some of that.
- **No passive DNS.** Resolutions are current, not historical. A C2 domain
  that has since moved won't pivot to where it used to live. A passive DNS
  source would slot into `hunt.resolve`; there isn't a free one worth
  depending on.
- **The weights are judgement.** They're in the profile, commented, and
  `explain` shows exactly how each one moved a score, but they aren't fitted
  to labelled data. Treat `likely` as "worth an analyst's look", not as a
  verdict.
- **crt.sh is slow and rate-limited.** prowl spaces requests three seconds
  apart and retries 429/5xx with backoff. A cold hunt that pivots through
  many domains takes a while; a cached one takes no time.

## References

- abuse.ch [ThreatFox API](https://threatfox.abuse.ch/api/) and [URLhaus API](https://urlhaus-api.abuse.ch/)
- [crt.sh](https://crt.sh/), [Team Cymru IP to ASN mapping](https://www.team-cymru.com/ip-asn-mapping)
- OASIS [STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html) (section 2.9 for deterministic ids), [MISP core format](https://www.misp-project.org/datamodels/), [MISP estimative-language taxonomy](https://www.misp-project.org/taxonomies.html#_estimative_language)
- Campaign facts in the profile: Cisco Talos, [BeaverTail and OtterCookie evolve](https://blog.talosintelligence.com/beavertail-and-ottercookie/); MITRE ATT&CK [S1246 BeaverTail](https://attack.mitre.org/software/S1246/); ANY.RUN, [InvisibleFerret technical analysis](https://anyrun.substack.com/p/invisibleferret-malware-technical); Elastic Security Labs, [New North Korean campaign uses fake coding interviews](https://www.elastic.co/security-labs/threat-command/contagious-interview-malware-svg-steganography)

See also [crumble](https://github.com/n4uu/crumble), which handles the
sample and network-capture side of the same campaign.

## License

MIT, see [LICENSE](LICENSE).
