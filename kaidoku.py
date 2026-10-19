#!/usr/bin/env python3
"""
0x41 / kaidoku - CVE intelligence, explained.

Usage:
    python kaidoku.py CVE-2021-44228
    python kaidoku.py CVE-2021-44228 --ai
    python kaidoku.py CVE-2021-44228 --ai --context "We run Java apps on Tomcat behind a load balancer"
    python kaidoku.py --file scan-report.txt
    cat cves.txt | python kaidoku.py -
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime

from sources import epss, kev, nvd
import analysis
import envprofile
import monomi_import
import triage
import ui
from ui import fail, good, info, warn

# Finds CVE IDs anywhere in text: "CVE-2021-44228", "cve_2021_44228", inside CSV cells, URLs, etc.
CVE_FIND = re.compile(r"CVE[-_]\d{4}[-_]\d{4,}", re.IGNORECASE)
NVD_DELAY = 6  # seconds between NVD lookups without a key (~5 per 30s allowed)


def extract_ids(text: str) -> list[str]:
    """Pull every CVE ID out of a blob of text, normalized, de-duplicated, in order."""
    found = (m.upper().replace("_", "-") for m in CVE_FIND.findall(text))
    return list(dict.fromkeys(found))


def gather_ids(args) -> list[str]:
    """Collect CVE IDs from the command line, --file, and stdin ('-')."""
    # Anything typed on the command line that isn't a CVE is probably a typo, so say so.
    for item in args.cves:
        if item != "-" and not CVE_FIND.fullmatch(item.strip()):
            raise ValueError(f"'{item}' doesn't look like a CVE ID (expected e.g. CVE-2021-44228)")

    chunks = []
    for item in args.cves:
        if item == "-":
            chunks.append(sys.stdin.read())
        else:
            chunks.append(item)
    if args.file:
        try:
            with open(args.file, encoding="utf-8", errors="replace") as f:
                chunks.append(f.read())
        except OSError as e:
            raise ValueError(f"Couldn't read {args.file}: {e.strerror}")

    return extract_ids("\n".join(chunks))


def lookup(cve_id: str, score: dict | None, catalog: dict, profile: dict | None, args, show_card: bool,
           found_on: list | None = None) -> dict | None:
    if show_card:
        info(f"Looking up {ui.paint(cve_id, ui.BOLD, ui.WHITE)} in the NVD...")
    try:
        record = nvd.collect(cve_id)
    except RuntimeError as e:
        fail(f"{cve_id}: {e}")
        if not os.environ.get("NVD_API_KEY"):
            warn("Without an NVD API key you're limited to ~5 lookups per 30s. A free key raises that (see README).")
        return None
    if record is None:
        fail(f"{cve_id} wasn't found in the NVD. Check the ID, or it may be reserved and not published yet.")
        return None

    kev.apply(record, catalog)  # CISA's own KEV data: fresher, and includes ransomware use
    verdict = triage.verdict(record, score)
    stack = envprofile.match(profile, record.get("affected") or [])
    result = {"cve": record, "epss": score, "verdict": verdict, "stack": stack, "found_on": found_on or []}

    if not show_card:
        good(f"{cve_id.ljust(16)}{ui.paint(verdict['label'], ui.GREY)}")
        return result

    print()
    if record.get("status") == "Rejected":
        warn(f"{cve_id} is REJECTED in the NVD (withdrawn or a duplicate). Details below are for reference only.")
        print()
    ui.cve_card(record, score, verdict, stack)

    if args.ai:
        print()
                # --context wins for this run; otherwise use the profile's description
        context = args.context or (profile or {}).get("description") or None
        info("Asking Claude to explain it...")
        try:
            briefing, model = analysis.explain(record, score, verdict, context, stack)
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
                f"model: {model}{' · tailored to your environment' if context else ''}*\n\n"
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
    parser.add_argument("cves", nargs="*", metavar="CVE",
                        help="one or more CVE IDs, e.g. CVE-2021-44228 (use - to read from stdin)")
    parser.add_argument("-f", "--file", metavar="FILE",
                        help="read CVE IDs from any text file: a list, a scanner export, a CSV...")
    parser.add_argument("--monomi", metavar="FILE",
                        help="read CVEs from a monomi --json file, keeping the host/IP each was found on")
    parser.add_argument("--cards", action="store_true", help="show the full card for every CVE in a batch")
    parser.add_argument("--ai", action="store_true", help="have Claude write a plain-English briefing (needs ANTHROPIC_API_KEY)")
    parser.add_argument("--context", metavar="TEXT", help="describe your environment so the AI tailors the impact (use with --ai)")
    parser.add_argument("--profile", metavar="FILE",
                        help="your environment profile (default: ~/.kaidoku/profile.json, if it exists)")
    parser.add_argument("--json", metavar="FILE", help="save results to a JSON file")
    parser.add_argument("--no-color", action="store_true", help="plain output (also respects NO_COLOR)")
    args = parser.parse_args()
    if args.no_color:
        ui.disable()
    print(ui.banner())

    if args.context and not args.ai:
        warn("--context only affects the AI briefing; add --ai to use it.")
    try:
        profile = envprofile.load(args.profile)
    except ValueError as e:
        fail(str(e))
        return 1
    if profile:
        info(f"Using profile {ui.paint(profile['name'], ui.BOLD, ui.WHITE)} "
             f"({len(profile['software'])} products listed)")
    try:
        ids = gather_ids(args)
    except ValueError as e:
        fail(str(e))
        return 1
    found_on = {}
    if args.monomi:
        try:
            target, monomi_ids, found_on = monomi_import.load(args.monomi)
        except ValueError as e:
            fail(str(e))
            return 1
        info(f"Read {len(monomi_ids)} CVE(s) from monomi's scan of {ui.paint(target, ui.BOLD, ui.WHITE)}")
        ids = list(dict.fromkeys(ids + monomi_ids))
    if not ids:
        fail("No CVE IDs found. Pass some on the command line, with --file, or pipe them in with -")
        return 1

    batch = len(ids) > 1
    show_cards = not batch or args.cards or args.ai
    if batch:
        info(f"Found {len(ids)} CVEs.")
        if args.ai and len(ids) > 5:
            warn(f"--ai will make {len(ids)} Claude requests (one per CVE).")
        if not os.environ.get("NVD_API_KEY"):
            mins, secs = divmod((len(ids) - 1) * NVD_DELAY, 60)
            warn(f"No NVD API key, so lookups are spaced out: about {mins}m {secs}s. A free key makes this ~10x faster.")
        print()

    # One EPSS request covers the whole batch
    try:
        scores = epss.collect_many(ids)
    except RuntimeError as e:
        warn(f"{e} (continuing without EPSS)")
        scores = {}

    # CISA's KEV catalog: read from the local cache when it's under 24h old
    try:
        catalog, kev_status = kev.load()
    except RuntimeError as e:
        warn(f"{e} (falling back to the NVD's copy of KEV data, without ransomware info)")
        catalog = {}
    else:
        if kev_status == "download":
            info(f"Downloaded CISA's KEV catalog ({len(catalog):,} entries), cached for 24h.")
        elif kev_status == "stale":
            warn("Couldn't refresh CISA's KEV catalog, so using the last saved copy.")

    results, missing = [], []
    for i, cve_id in enumerate(ids):
        if i:
            if show_cards:
                print("\n" + ui.paint("═" * 60, ui.GREY) + "\n")
            if not os.environ.get("NVD_API_KEY"):
                time.sleep(NVD_DELAY)  # stay under the NVD's no-key rate limit
        r = lookup(cve_id, scores.get(cve_id), catalog, profile, args, show_card=show_cards, found_on=found_on.get(cve_id))
        if r:
            results.append(r)
        else:
            missing.append(cve_id)

    if batch and results:
        results.sort(key=triage.rank_key)
        print()
        ui.summary_table(results, missing)

    if args.json and results:
        with open(args.json, "w") as f:
            json.dump(results if len(results) > 1 else results[0], f, indent=2)
        print()
        good(f"Saved results to {args.json}")

    return 0 if results else 1


if __name__ == "__main__":
    sys.exit(main())
