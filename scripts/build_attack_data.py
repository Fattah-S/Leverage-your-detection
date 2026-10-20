"""Build the compact MITRE ATT&CK file the platform uses.

Usage:
    python scripts/build_attack_data.py path/to/enterprise-attack.json [release]

Download enterprise-attack.json from https://github.com/mitre/cti
(enterprise-attack/enterprise-attack.json). The output keeps only what the
platform needs: techniques (id, name, tactics, platforms), tactic order and
threat-group technique usage.

MITRE ATT&CK(R) is a registered trademark of The MITRE Corporation. ATT&CK data
is used under the ATT&CK Terms of Use: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "data" / "attack" / "enterprise-compact.json"


def ext_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def live(obj: dict) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def main(src: str, release: str) -> None:
    bundle = json.loads(Path(src).read_text())
    objs = bundle["objects"]
    by_id = {o["id"]: o for o in objs}

    tactics = {o["x_mitre_shortname"]: {"id": ext_id(o), "name": o["name"]}
               for o in objs if o["type"] == "x-mitre-tactic" and live(o)}
    matrix = next(o for o in objs if o["type"] == "x-mitre-matrix")
    tactic_order = [by_id[ref]["x_mitre_shortname"] for ref in matrix["tactic_refs"]]

    techniques = {}
    for o in objs:
        if o["type"] != "attack-pattern" or not live(o):
            continue
        tid = ext_id(o)
        if not tid:
            continue
        techniques[tid] = {
            "name": o["name"],
            "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", [])
                        if p.get("kill_chain_name") == "mitre-attack"],
            "platforms": o.get("x_mitre_platforms", []),
            "is_sub": bool(o.get("x_mitre_is_subtechnique")),
        }
    # Sub-technique names read better with their parent: "OS Credential Dumping: LSASS Memory"
    for tid, t in techniques.items():
        if t["is_sub"]:
            parent = techniques.get(tid.split(".")[0])
            if parent:
                t["name"] = f"{parent['name']}: {t['name']}"

    groups = {}
    for o in objs:
        if o["type"] == "intrusion-set" and live(o):
            gid = ext_id(o)
            if gid:
                groups[o["id"]] = {"id": gid, "name": o["name"],
                                   "aliases": o.get("aliases", []), "techniques": set()}
    for r in objs:
        if r["type"] == "relationship" and r.get("relationship_type") == "uses" and live(r):
            src_ref, tgt = r["source_ref"], by_id.get(r["target_ref"])
            if src_ref in groups and tgt and tgt["type"] == "attack-pattern" and live(tgt):
                tid = ext_id(tgt)
                if tid:
                    groups[src_ref]["techniques"].add(tid)

    # Retired techniques and what replaced them (STIX "revoked-by" relationships)
    revoked_by = {}
    for r in objs:
        if r["type"] == "relationship" and r.get("relationship_type") == "revoked-by":
            s, t = by_id.get(r["source_ref"]), by_id.get(r["target_ref"])
            if s and t and s["type"] == "attack-pattern" and ext_id(s) and ext_id(t):
                revoked_by[ext_id(s)] = ext_id(t)

    out = {
        "attack_release": release,
        "revoked_by": dict(sorted(revoked_by.items())),
        "source": "https://github.com/mitre/cti",
        "terms": "https://attack.mitre.org/resources/legal-and-branding/terms-of-use/",
        "tactic_order": tactic_order,
        "tactics": tactics,
        "techniques": dict(sorted(techniques.items())),
        "groups": {g["id"]: {"name": g["name"], "aliases": g["aliases"],
                             "techniques": sorted(g["techniques"])}
                   for g in sorted(groups.values(), key=lambda g: g["id"])},
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, indent=1))
    print(f"wrote {OUT} ({len(techniques)} techniques, {len(out['groups'])} groups)")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "unknown")
