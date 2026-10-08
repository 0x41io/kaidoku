#!/usr/bin/env python3
"""
0x41 / kaidoku - CVE intelligence, explained.

Usage:
    python kaidoku.py CVE-2021-44228
    python kaidoku.py CVE-2021-44228 --ai
    python kaidoku.py CVE-2021-44228 --ai --context "We run Java apps on Tomcat behind a load balancer"
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime

from sources import epss, nvd
import analysis
import triage
import ui
from ui import fail, good, info, warn

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def clean_cve(raw: str) -> str:
    c = raw.strip().upper().replace("_", "-")
    if not CVE_RE.match(c):
        raise ValueError(f"'{raw}' doesn't look like a CVE ID (expected e.g. CVE-2021-44228)")
    return c


def lookup(cve_id: str, args) -> dict | None:
    info(f"Looking up {ui.paint(cve_id, ui.BOLD, ui.WHITE)} in the NVD...")
    try:
        record = nvd.collect(cve_id)
    except RuntimeError as e:
        fail(str(e))
        if not os.environ.get("NVD_API_KEY"):
            warn("Without an NVD API key you're limited to ~5 lookups per 30s. A free key raises that (see README).")
        return None
    if record is None:
        fail(f"{cve_id} wasn't found in the NVD. Check the ID, or it may be reserved and not published yet.")
        return None

    try:
        score = epss.collect(cve_id)
    except RuntimeError as e:
        warn(f"{e} (continuing without EPSS)")
        score = None

    verdict = triage.verdict(record, score)
    result = {"cve": record, "epss": score, "verdict": verdict}

    print()
    if record.get("status") == "Rejected":
        warn(f"{cve_id} is REJECTED in the NVD (withdrawn or a duplicate). Details below are for reference only.")
        print()
    ui.cve_card(record, score, verdict)

    if args.ai:
        print()
        info("Asking Claude to explain it...")
        try:
            briefing, model = analysis.explain(record, score, verdict, args.context)
        except Exception as e:  # missing key, network, API errors
            fail(f"AI briefing failed: {e}")
        else:
            result["briefing"] = briefing
            os.makedirs("reports", exist_ok=True)
            stamp = datetime.now().strftime("%Y-%m-%d_%H%M")
            path = os.path.join("reports", f"{cve_id}_{stamp}.md")
            header = (
                f"# kaidoku briefing: {cve_id}\n\n"
                f"*Generated {datetime.now():%Y-%m-%d %H:%M} · verdict: {verdict['label']} · "
                f"model: {model}{' · tailored to provided context' if args.context else ''}*\n\n"
            )
            with open(path, "w") as f:
                f.write(header + briefing + "\n")
            print()
            ui.render_report(briefing)
            print()
            good(f"Briefing saved to {path}")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="0x41 / kaidoku - CVE intelligence, explained")
    parser.add_argument("cves", nargs="+", metavar="CVE", help="one or more CVE IDs, e.g. CVE-2021-44228")
    parser.add_argument("--ai", action="store_true", help="have Claude write a plain-English briefing (needs ANTHROPIC_API_KEY)")
    parser.add_argument("--context", metavar="TEXT", help="describe your environment so the AI tailors the impact (use with --ai)")
    parser.add_argument("--json", metavar="FILE", help="save results to a JSON file")
    parser.add_argument("--no-color", action="store_true", help="plain output (also respects NO_COLOR)")
    args = parser.parse_args()
    if args.no_color:
        ui.disable()
    print(ui.banner())

    if args.context and not args.ai:
        warn("--context only affects the AI briefing; add --ai to use it.")

    try:
        ids = list(dict.fromkeys(clean_cve(c) for c in args.cves))  # de-duplicate, keep order
    except ValueError as e:
        fail(str(e))
        return 1

    results = []
    for i, cve_id in enumerate(ids):
        if i:
            print("\n" + ui.paint("═" * 60, ui.GREY) + "\n")
            if not os.environ.get("NVD_API_KEY"):
                time.sleep(6)  # stay under the NVD's no-key rate limit
        r = lookup(cve_id, args)
        if r:
            results.append(r)

    if args.json and results:
        with open(args.json, "w") as f:
            json.dump(results if len(results) > 1 else results[0], f, indent=2)
        print()
        good(f"Saved results to {args.json}")

    return 0 if results else 1


if __name__ == "__main__":
    sys.exit(main())
