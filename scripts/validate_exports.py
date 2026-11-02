#!/usr/bin/env python3
"""Validate prowl's exports with the reference implementations: the OASIS
stix2 library (strict parse, pattern grammar, deterministic SCO ids) and
PyMISP. Run after `prowl demo` or any hunt:

    python3 scripts/validate_exports.py prowl-out
"""
import json
import sys

import stix2
from pymisp import MISPEvent
from stix2patterns.validator import run_validator


def main(out: str) -> int:
    failures = 0

    raw = json.load(open(f"{out}/stix-bundle.json"))
    bundle = stix2.parse(raw, allow_custom=False)
    ids = [o.id for o in bundle.objects]
    if len(ids) != len(set(ids)):
        print("STIX: duplicate object ids")
        failures += 1
    known = set(ids)
    for o in bundle.objects:
        if o.type == "indicator":
            errs = run_validator(o.pattern)
            if errs:
                print(f"STIX: bad pattern {o.pattern}: {errs}")
                failures += 1
        if o.type == "relationship":
            for ref in (o.source_ref, o.target_ref):
                if ref not in known:
                    print(f"STIX: dangling reference {ref}")
                    failures += 1
        if o.type == "ipv4-addr" and stix2.IPv4Address(value=o.value).id != o.id:
            print(f"STIX: {o.value} id {o.id} is not the spec's deterministic id")
            failures += 1
        if o.type == "domain-name" and stix2.DomainName(value=o.value).id != o.id:
            print(f"STIX: {o.value} id {o.id} is not the spec's deterministic id")
            failures += 1
    counts = {}
    for o in bundle.objects:
        counts[o.type] = counts.get(o.type, 0) + 1
    print("STIX ok:", counts)

    ev = MISPEvent()
    ev.load_file(f"{out}/misp-event.json")
    if not ev.attributes:
        print("MISP: no attributes")
        failures += 1
    print(f"MISP ok: {len(ev.attributes)} attributes, {sum(a.to_ids for a in ev.attributes)} flagged to_ids")

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "prowl-out"))
