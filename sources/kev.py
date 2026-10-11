"""
CISA Known Exploited Vulnerabilities (KEV) catalog, read straight from CISA.

The NVD copies CISA's KEV fields into its records, but it can lag behind, and
it leaves out one useful field: whether the CVE is known to be used in
ransomware campaigns. CISA publishes the whole catalog as one JSON file
(1,700+ entries and growing), so we download it, keep a local copy for 24 hours,
and look CVEs up in memory.
"""

import json
import os
import time

import requests

from sources import USER_AGENT

FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# cache/ sits next to kaidoku.py, so the same cache is used no matter where you run it from
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_DIR = os.path.join(PROJECT_DIR, "cache")
CACHE_FILE = os.path.join(CACHE_DIR, "kev.json")
MAX_AGE = 24 * 60 * 60  # seconds: refresh once a day


def _download(timeout: int = 30) -> dict:
    """Fetch the feed and save it to the cache. Returns the parsed JSON."""
    resp = requests.get(FEED_URL, headers={"User-Agent": USER_AGENT}, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data.get("vulnerabilities"), list):
        raise ValueError("unexpected KEV feed format")

    # Write to a temp file first, then swap it in. If we crash mid-write, the
    # old cache is still intact instead of half a file.
    os.makedirs(CACHE_DIR, exist_ok=True)
    tmp = CACHE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, CACHE_FILE)
    return data


def _read_cache() -> dict:
    with open(CACHE_FILE, encoding="utf-8") as f:
        return json.load(f)


def _index(data: dict) -> dict[str, dict]:
    """Turn the feed into {'CVE-2021-44228': {...}, ...} in kaidoku's own field names."""
    catalog = {}
    for v in data.get("vulnerabilities", []):
        cve_id = (v.get("cveID") or "").upper()
        if not cve_id:
            continue
        catalog[cve_id] = {
            "name": v.get("vulnerabilityName"),
            "date_added": v.get("dateAdded"),
            "action_due": v.get("dueDate"),
            "required_action": v.get("requiredAction"),
            "ransomware": (v.get("knownRansomwareCampaignUse") or "").lower() == "known",
        }
    return catalog


def load() -> tuple[dict[str, dict], str]:
    """Return (catalog, status). status is 'cache', 'download', or 'stale'.

    - Fresh cache (under 24h old): read it, no network.
    - Old or missing cache: download a new copy.
    - Download fails but an old copy exists: use the old copy ('stale').
    - Download fails and there's no copy: raise RuntimeError.
    """
    age = time.time() - os.path.getmtime(CACHE_FILE) if os.path.exists(CACHE_FILE) else None

    if age is not None and age < MAX_AGE:
        try:
            return _index(_read_cache()), "cache"
        except (OSError, ValueError):
            pass  # unreadable or corrupt cache: fall through and download a new one

    try:
        return _index(_download()), "download"
    except (requests.RequestException, ValueError, OSError) as e:
        if age is not None:
            try:
                return _index(_read_cache()), "stale"
            except (OSError, ValueError):
                pass
        raise RuntimeError(f"CISA KEV feed unavailable: {e}")


def apply(record: dict, catalog: dict[str, dict]) -> None:
    """Update an NVD record's 'kev' field with CISA's own (fresher) data, in place."""
    entry = catalog.get(record.get("id", ""))
    if entry:
        record["kev"] = dict(entry)
    elif record.get("kev"):
        record["kev"].setdefault("ransomware", None)  # NVD says KEV, CISA's copy doesn't: unknown
