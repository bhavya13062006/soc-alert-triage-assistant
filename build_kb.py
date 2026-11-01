"""Download MITRE ATT&CK (Enterprise) STIX data and convert it to a compact JSON knowledge base.

Usage: python scripts/build_kb.py [path/to/enterprise-attack.json]
If no path is given the file is downloaded from MITRE's public GitHub repo.
"""
import json, re, sys, pathlib, urllib.request

URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
OUT = pathlib.Path(__file__).parent.parent / "data" / "attack_kb.json"

def load(path):
    if path:
        return json.loads(pathlib.Path(path).read_text())
    print("Downloading ATT&CK STIX bundle (~55 MB)...")
    with urllib.request.urlopen(URL, timeout=120) as r:
        return json.loads(r.read())

def clean(text):
    text = re.sub(r"\(Citation:[^)]*\)", "", text or "")          # drop citation markers
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)          # markdown links -> text
    text = re.sub(r"<code>|</code>", "", text)
    return re.sub(r"\s+", " ", text).strip()

def main():
    objs = load(sys.argv[1] if len(sys.argv) > 1 else None)["objects"]
    by_id = {o["id"]: o for o in objs}
    mitigations = {}
    for o in objs:
        if o.get("type") == "relationship" and o.get("relationship_type") == "mitigates" and not o.get("revoked"):
            src, tgt = by_id.get(o["source_ref"]), o["target_ref"]
            if src and src.get("type") == "course-of-action" and not src.get("revoked"):
                note = clean(o.get("description", ""))[:260]
                mitigations.setdefault(tgt, []).append(f'{src["name"]}: {note}' if note else src["name"])
    # Procedure examples: how real groups/malware/tools use each technique (tool names, commands).
    examples, software = {}, {}
    for o in objs:
        if o.get("type") == "relationship" and o.get("relationship_type") == "uses" and not o.get("revoked"):
            src = by_id.get(o["source_ref"])
            if not src or src.get("revoked") or o["target_ref"] not in by_id:
                continue
            if by_id[o["target_ref"]].get("type") != "attack-pattern":
                continue
            if src.get("type") in ("malware", "tool"):
                software.setdefault(o["target_ref"], set()).add(src["name"])
            note = clean(o.get("description", ""))[:260]
            if note:
                examples.setdefault(o["target_ref"], []).append(note)
    kb = []
    for o in objs:
        if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ext = next((r for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if not ext:
            continue
        kb.append({
            "id": ext["external_id"],
            "name": o["name"],
            "tactics": [p["phase_name"].replace("-", " ").title() for p in o.get("kill_chain_phases", [])],
            "platforms": o.get("x_mitre_platforms", []),
            "desc": clean(o.get("description", ""))[:1500],
            "detection": clean(o.get("x_mitre_detection", ""))[:600],
            "mitigations": mitigations.get(o["id"], [])[:5],
            "examples": examples.get(o["id"], [])[:25],
            "software": sorted(software.get(o["id"], []))[:30],
            "url": ext.get("url", ""),
        })
    kb.sort(key=lambda t: t["id"])
    OUT.write_text(json.dumps(kb))
    print(f"Wrote {len(kb)} techniques/sub-techniques to {OUT}")

if __name__ == "__main__":
    main()
