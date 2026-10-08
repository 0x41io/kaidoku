"""
EPSS (Exploit Prediction Scoring System) collector, run by FIRST.org.

EPSS estimates the probability that a CVE will be exploited in the wild in
the next 30 days, updated daily. CVSS says how bad it *could* be; EPSS says
how likely it is to actually be used. Free API, no key.
"""

import requests

from sources import USER_AGENT

API_URL = "https://api.first.org/data/v1/epss"


def collect(cve_id: str, timeout: int = 20) -> dict | None:
    """Return {'probability': 0.94, 'percentile': 0.999, 'date': '...'} or None if unscored."""
    try:
        resp = requests.get(API_URL, params={"cve": cve_id}, headers={"User-Agent": USER_AGENT}, timeout=timeout)
        resp.raise_for_status()
        data = resp.json().get("data", [])
    except (requests.RequestException, ValueError) as e:
        raise RuntimeError(f"EPSS lookup failed: {e}")
    if not data:
        return None
    row = data[0]
    return {
        "probability": float(row["epss"]),
        "percentile": float(row["percentile"]),
        "date": row.get("date"),
    }
