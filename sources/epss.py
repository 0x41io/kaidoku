"""
EPSS (Exploit Prediction Scoring System) collector, run by FIRST.org.

EPSS estimates the probability that a CVE will be exploited in the wild in
the next 30 days, updated daily. CVSS says how bad it *could* be; EPSS says
how likely it is to actually be used. Free API, no key.
"""

import requests

from sources import USER_AGENT

API_URL = "https://api.first.org/data/v1/epss"
CHUNK = 50  # CVEs per request; keeps the URL a sane length


def collect_many(cve_ids: list[str], timeout: int = 20) -> dict[str, dict]:
    """Score many CVEs in as few requests as possible.

    Returns {'CVE-2021-44228': {'probability': 0.94, 'percentile': 0.999, 'date': '...'}, ...}.
    CVEs that EPSS hasn't scored are simply missing from the result.
    """
    scores = {}
    for i in range(0, len(cve_ids), CHUNK):
        batch = cve_ids[i:i + CHUNK]
        params = {"cve": ",".join(batch), "limit": len(batch)}
        try:
            resp = requests.get(API_URL, params=params, headers={"User-Agent": USER_AGENT}, timeout=timeout)
            resp.raise_for_status()
            rows = resp.json().get("data", [])
        except (requests.RequestException, ValueError) as e:
            raise RuntimeError(f"EPSS lookup failed: {e}")
        for row in rows:
            scores[row["cve"]] = {
                "probability": float(row["epss"]),
                "percentile": float(row["percentile"]),
                "date": row.get("date"),
            }
    return scores


def collect(cve_id: str, timeout: int = 20) -> dict | None:
    """Score a single CVE, or None if EPSS hasn't scored it."""
    return collect_many([cve_id], timeout=timeout).get(cve_id)
