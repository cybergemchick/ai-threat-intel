#!/usr/bin/env python3
"""
AI Security Incident Tracker: CLI Viewer
CyberGemChick | github.com/cybergemchick

Usage:
    python view_incidents.py
    python view_incidents.py --severity CRITICAL
    python view_incidents.py --atlas AML.T0051
    python view_incidents.py --owasp LLM01
    python view_incidents.py --search "injection"
    python view_incidents.py --format markdown
    python view_incidents.py --format atlas     # ATLAS coverage table (official names)
"""

import json
import argparse
import sys
import os

DATA_FILE = os.path.join(os.path.dirname(__file__), "incidents.json")
ATLAS_FILE = os.path.join(os.path.dirname(__file__), "atlas_techniques.json")


def load_atlas_names():
    """Official MITRE ATLAS technique names, keyed by ID (see atlas_techniques.json)."""
    try:
        with open(ATLAS_FILE) as f:
            return json.load(f)["techniques"]
    except (OSError, KeyError, ValueError):
        return {}


def load_incidents():
    with open(DATA_FILE) as f:
        data = json.load(f)
    return data["incidents"], data["metadata"]


def filter_incidents(incidents, severity=None, atlas=None, owasp=None, search=None):
    results = incidents
    if severity:
        results = [i for i in results if i.get("severity", "").upper() == severity.upper()]
    if atlas:
        results = [i for i in results if any(atlas.upper() in t for t in i.get("atlas_techniques", []))]
    if owasp:
        results = [i for i in results if any(owasp.upper() in t for t in i.get("owasp_llm", []))]
    if search:
        s = search.lower()
        results = [i for i in results if
                   s in i.get("title", "").lower() or
                   s in i.get("summary", "").lower() or
                   s in i.get("attack_type", "").lower()]
    return results


def print_table(incidents):
    SEV_ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
    print(f"\n{'ID':>8}  {'Date':>8}  {'Sev':>5}  {'Title':<55}  {'Attack Type'}")
    print("-" * 110)
    for inc in incidents:
        sev = inc.get("severity", "?")
        icon = SEV_ICONS.get(sev, "⚪")
        print(f"  {inc['id']:>6}  {inc['date']:>8}  {icon} {sev:<8}  {inc['title'][:53]:<55}  {inc.get('attack_type','')[:40]}")


def print_detail(inc):
    SEV_COLORS = {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[93m", "LOW": "\033[92m"}
    RESET = "\033[0m"
    sev = inc.get("severity", "")
    color = SEV_COLORS.get(sev, "")

    print(f"\n{'='*70}")
    print(f"  {inc['id']}: {inc['title']}")
    print(f"{'='*70}")
    print(f"  Date:      {inc.get('date', 'N/A')}")
    print(f"  Vendor:    {inc.get('vendor', 'N/A')}")
    print(f"  Product:   {inc.get('product', 'N/A')}")
    print(f"  Severity:  {color}{sev}{RESET}")
    print(f"  Type:      {inc.get('attack_type', 'N/A')}")
    print(f"\n  Summary:\n  {inc.get('summary', '')}")
    names = load_atlas_names()
    print("\n  ATLAS:")
    for t in inc.get("atlas_techniques", []):
        print(f"    - {t}  {names.get(t, '')}")
    print(f"  OWASP LLM: {', '.join(inc.get('owasp_llm', [])) or 'N/A'}")
    print(f"  Impact:    {inc.get('impact', 'N/A')}")
    print(f"  Disclosed: {inc.get('disclosed_by', 'N/A')}")
    print(f"  Status:    {inc.get('patch_status', 'N/A')}")
    print(f"\n  References:")
    for ref in inc.get("references", []):
        print(f"    - {ref}")


def print_markdown(incidents):
    print("# AI Security Incident Report\n")
    print("| ID | Date | Severity | Title | Attack Type | ATLAS | OWASP |")
    print("|---|---|---|---|---|---|---|")
    for inc in incidents:
        atlas = ", ".join(inc.get("atlas_techniques", []))
        owasp = ", ".join(inc.get("owasp_llm", []))
        print(f"| {inc['id']} | {inc['date']} | {inc['severity']} | {inc['title']} | {inc.get('attack_type','')} | {atlas} | {owasp} |")


def print_atlas_table(incidents):
    """Markdown table of every ATLAS technique referenced, with the incidents that use it."""
    names = load_atlas_names()
    by_tech = {}
    for inc in incidents:
        for t in inc.get("atlas_techniques", []):
            by_tech.setdefault(t, []).append(inc["id"])

    def sort_key(tid):
        parts = tid.replace("AML.T", "").split(".")
        return tuple(int(p) for p in parts)

    print("| Technique | Name | Incidents |")
    print("|-----------|------|-----------|")
    for t in sorted(by_tech, key=sort_key):
        print(f"| {t} | {names.get(t, '?')} | {', '.join(by_tech[t])} |")


def stats(incidents):
    from collections import Counter
    sev_counts = Counter(i.get("severity") for i in incidents)
    atlas_counts = Counter(t for i in incidents for t in i.get("atlas_techniques", []))
    owasp_counts = Counter(t for i in incidents for t in i.get("owasp_llm", []))

    print(f"\n{'─'*40}")
    print(f"  Total incidents: {len(incidents)}")
    print(f"\n  By Severity:")
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        print(f"    {s:<10} {sev_counts.get(s, 0)}")
    print(f"\n  Top ATLAS Techniques:")
    for tech, count in atlas_counts.most_common(5):
        print(f"    {tech:<20} {count}")
    print(f"\n  Top OWASP Categories:")
    for cat, count in owasp_counts.most_common(5):
        print(f"    {cat:<15} {count}")


def main():
    parser = argparse.ArgumentParser(description="AI Security Incident Tracker CLI")
    parser.add_argument("--severity", help="Filter by severity (CRITICAL/HIGH/MEDIUM/LOW)")
    parser.add_argument("--atlas", help="Filter by ATLAS technique (e.g. AML.T0051)")
    parser.add_argument("--owasp", help="Filter by OWASP LLM category (e.g. LLM01)")
    parser.add_argument("--search", help="Search by keyword in title/summary")
    parser.add_argument("--id", help="Show detail for specific incident ID")
    parser.add_argument("--format", choices=["table", "markdown", "stats", "atlas"], default="table")
    args = parser.parse_args()

    incidents, meta = load_incidents()

    if args.id:
        matches = [i for i in incidents if i["id"] == args.id.upper()]
        if matches:
            print_detail(matches[0])
        else:
            print(f"Incident {args.id} not found.")
        return

    filtered = filter_incidents(incidents, args.severity, args.atlas, args.owasp, args.search)

    if not filtered:
        print("No incidents match the filter criteria.")
        return

    if args.format == "markdown":
        print_markdown(filtered)
    elif args.format == "atlas":
        print_atlas_table(filtered)
    elif args.format == "stats":
        stats(filtered)
    else:
        print_table(filtered)
        print(f"\n  {len(filtered)} incident(s) found. Use --id INC-XXX for details.\n")


if __name__ == "__main__":
    main()
