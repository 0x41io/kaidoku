"""
Kaidoku as a library (v0.8): what the 0x41 pipeline (`0x41 run`) calls.

Two functions, both quiet: they print nothing and write no files, so the
caller decides what to show and where to save. They return the same data the
command line works from, so `kaidoku ... --json` and these agree.

    from kaidoku import api
    out = api.explain_history("akashi/history/example.com.jsonl", ai=True)
    out = api.lookup_cves(["CVE-2021-44228"], ai=True)

What these return is a contract: tests/test_api.py locks the keys, so a
change that would break the pipeline fails a test first. Add keys freely;
renaming or removing one needs API_VERSION bumped and the pipeline updated.
"""

import os
import time

from kaidoku import akashi_import, analysis, envprofile, preconditions, triage
from kaidoku.sources import VERSION, epss, kev, nvd

API_VERSION = 1


def explain_history(path: str, ai: bool = False, context: str | None = None) -> dict:
    """Read an akashi proof history and explain each lead.

    Returns {"kaidoku_version", "api_version", "target", "leads": [...]},
    leads ranked most urgent first, each as akashi_import.load() builds it
    (rule, name, id, key, state, label, headline, evidence, fix, owner,
    reason, timeline...). With ai=True each lead also gets "briefing" (and
    "model"), or "briefing_error" if that one failed. akashi's verdicts are
    never changed. Raises ValueError for a file that isn't akashi history.
    """
    target, leads = akashi_import.load(path)
    if ai:
        for lead in leads:
            try:
                lead["briefing"], lead["model"] = analysis.explain_finding(lead, target, context)
            except Exception as e:  # missing key, network, API errors: keep going
                lead["briefing_error"] = str(e)
    return {"kaidoku_version": VERSION, "api_version": API_VERSION, "target": target, "leads": leads}


def lookup_cves(ids: list[str], ai: bool = False, context: str | None = None,
                profile: dict | None = None, found_on: dict | None = None,
                exclusions: list[str] | None = None) -> dict:
    """Look up CVEs: NVD + EPSS + CISA KEV, the rule-based verdict, and with
    ai=True a briefing each.

    Returns {"kaidoku_version", "api_version", "results": [...], "missing": [...],
    "warnings": [...]}. Results are ranked like the batch table (KEV, then
    EPSS, then CVSS), each {"cve", "epss", "verdict", "stack", "found_on"}
    plus "briefing" / "model" or "briefing_error" with ai=True: the same
    shape as `kaidoku --json`. "missing" lists IDs the NVD didn't return.
    found_on maps a CVE ID to where monomi saw it. Since v0.10 each result
    also has "preconditions" (what an attack needs, see preconditions.py)
    and "excluded_by" (the classes of `exclusions` it falls under; [] when
    none or no exclusions were given). Neither changes the verdict.
    """
    ids = list(dict.fromkeys(i.strip().upper() for i in ids if i and i.strip()))
    found_on = found_on or {}
    warnings = []
    try:
        scores = epss.collect_many(ids) if ids else {}
    except RuntimeError as e:
        warnings.append(f"EPSS unavailable: {e}")
        scores = {}
    try:
        catalog, kev_status = kev.load()
        if kev_status == "stale":
            warnings.append("CISA's KEV catalog couldn't be refreshed: using the last saved copy")
    except RuntimeError as e:
        warnings.append(f"CISA KEV unavailable, using the NVD's copy: {e}")
        catalog = {}

    results, missing = [], []
    for n, cve_id in enumerate(ids):
        if n:
            time.sleep(nvd.DELAY_KEY if os.environ.get("NVD_API_KEY") else nvd.DELAY)
        try:
            record = nvd.collect(cve_id)
        except RuntimeError as e:
            warnings.append(f"{cve_id}: {e}")
            missing.append(cve_id)
            continue
        if record is None:
            missing.append(cve_id)
            continue
        kev.apply(record, catalog)
        score = scores.get(cve_id)
        verdict = triage.verdict(record, score)
        stack = envprofile.match(profile, record.get("affected") or [])
        pre = preconditions.tags(record)
        result = {"cve": record, "epss": score, "verdict": verdict, "stack": stack,
                  "found_on": found_on.get(cve_id) or [], "preconditions": pre,
                  "excluded_by": preconditions.excluded_by(pre, exclusions)}
        if ai:
            try:
                result["briefing"], result["model"] = analysis.explain(
                    record, score, verdict, context or (profile or {}).get("description") or None,
                    stack, result["found_on"], pre, result["excluded_by"])
            except Exception as e:  # missing key, network, API errors: keep going
                result["briefing_error"] = str(e)
        results.append(result)

    results.sort(key=triage.rank_key)
    return {"kaidoku_version": VERSION, "api_version": API_VERSION,
            "results": results, "missing": missing, "warnings": warnings}
