#!/usr/bin/env python3
"""
export_data.py -- derive the machine-readable views in data/ from
THREAT-REPOSITORY.md, so the CSVs can never drift from the prose.

    python3 tools/export_data.py

Writes data/threats.csv and data/mitre-mappings.csv.
"""
import csv
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "THREAT-REPOSITORY.md")
OUT = os.path.join(ROOT, "data")

DOMAIN_NAME = {
    "RAN": "Radio access and radio-link simulation",
    "N2": "N2 / NGAP control plane",
    "N3": "N3 / GTP-U user plane",
    "N4": "N4 / PFCP session management",
    "SUB": "Subscriber identity and credential privacy",
    "DB": "Subscriber data repository",
    "VIRT": "Virtualisation, containers and segmentation",
    "AI": "AI/ML security of the IDS pipeline",
    "OPS": "Operational security and detection posture",
}


def one_line(t):
    return re.sub(r"\s+", " ", t).strip()


def main():
    text = open(SRC, encoding="utf-8").read()
    chunks = re.split(r"^### (TR-[A-Z0-9-]+) — (.+)$", text, flags=re.M)
    ids, titles, bodies = chunks[1::3], chunks[2::3], chunks[3::3]

    threats, mappings = [], []
    for tid, title, body in zip(ids, titles, bodies):
        domain = tid.split("-")[1]
        meta = re.search(r"\|\s*(RAN|N2|N3|N4|SUB|DB|VIRT|AI|OPS)\s*\|\s*\*\*(\w+)\*\*\s*\|"
                         r"\s*(\w+)\s*\|\s*(.+?)\s*\|", body)
        sev = meta.group(2) if meta else ""
        conf = meta.group(3) if meta else ""
        assets = meta.group(4).replace("`", "") if meta else ""

        def section(name, nxt):
            m = re.search(r"\*\*%s\*\*\s*(.*?)(?=\*\*(?:%s)\*\*)" % (name, nxt), body, re.S)
            return one_line(m.group(1)) if m else ""

        threats.append({
            "id": tid,
            "title": one_line(title),
            "domain": domain,
            "domain_name": DOMAIN_NAME.get(domain, ""),
            "severity": sev,
            "confidence": conf,
            "assets": assets,
            "what_happened": section("What happened\\.", "Why this is a threat\\."),
            "impact": section("Impact\\.", "Detection\\."),
            "detection": section("Detection\\.", "Mitigation\\."),
            "mitigation": section("Mitigation\\.", "References\\."),
        })

        ttp = re.search(r"\*\*TTP mapping\.\*\*(.*?)(?=\*\*Impact\.\*\*)", body, re.S)
        if ttp:
            for row in re.finditer(
                    r"^\|\s*(ATT&CK|ATLAS|FiGHT)\s*\|\s*\[([^\]]+)\]\(([^)]+)\)\s*\|"
                    r"\s*([^|]+?)\s*\|\s*(.+?)\s*\|\s*$", ttp.group(1), re.M):
                mappings.append({
                    "threat_id": tid, "framework": row.group(1), "technique_id": row.group(2),
                    "technique_name": row.group(4), "url": row.group(3),
                    "rationale": one_line(row.group(5)),
                })

    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "threats.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(threats[0].keys()))
        w.writeheader()
        w.writerows(threats)
    with open(os.path.join(OUT, "mitre-mappings.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(mappings[0].keys()))
        w.writeheader()
        w.writerows(mappings)
    print("threats.csv: %d rows" % len(threats))
    print("mitre-mappings.csv: %d rows" % len(mappings))
    from collections import Counter
    print("  by framework:", dict(Counter(m["framework"] for m in mappings)))
    print("  distinct techniques:", len({(m["framework"], m["technique_id"]) for m in mappings}))


if __name__ == "__main__":
    main()
