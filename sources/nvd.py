"""
NVD (National Vulnerability Database) collector.

The NVD API 2.0 is free. Without an API key it allows about 5 requests per
30 seconds; with a free key (set NVD_API_KEY) it allows 50. Each CVE record
also carries CISA's "Known Exploited Vulnerabilities" fields when the CVE is
on that list, so one request tells us whether it's being exploited in the wild.
"""

import os
import time

import requests

from sources import USER_AGENT

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Plain-English labels for CVSS v3 vector parts
VECTOR_LABELS = {
    "AV": ("Attack vector", {"N": "Network (remote)", "A": "Adjacent network", "L": "Local access", "P": "Physical access"}),
    "AC": ("Attack complexity", {"L": "Low", "H": "High"}),
    "PR": ("Privileges needed", {"N": "None", "L": "Low", "H": "High"}),
    "UI": ("User interaction", {"N": "None", "R": "Required"}),
    "S": ("Scope", {"U": "Unchanged", "C": "Changed (can affect other components)"}),
    "C": ("Confidentiality impact", {"H": "High", "L": "Low", "N": "None"}),
    "I": ("Integrity impact", {"H": "High", "L": "Low", "N": "None"}),
    "A": ("Availability impact", {"H": "High", "L": "Low", "N": "None"}),
}

REF_PRIORITY = ["Patch", "Vendor Advisory", "Mitigation", "Exploit", "Third Party Advisory"]


def fetch(cve_id: str, retries: int = 3, timeout: int = 30) -> dict | None:
    """Return the raw NVD 'cve' object, or None if the CVE doesn't exist."""
    headers = {"User-Agent": USER_AGENT}
    if os.environ.get("NVD_API_KEY"):
        headers["apiKey"] = os.environ["NVD_API_KEY"]
    last_error = None

    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(API_URL, params={"cveId": cve_id}, headers=headers, timeout=timeout)
            if resp.status_code == 200:
                vulns = resp.json().get("vulnerabilities", [])
                return vulns[0]["cve"] if vulns else None
            if resp.status_code == 404:
                return None
            last_error = f"HTTP {resp.status_code}"
            # 403/429 = rate limited (no key: ~5 requests per 30s), 5xx = NVD hiccup
        except (requests.RequestException, ValueError) as e:
            last_error = str(e)
        if attempt < retries:
            time.sleep(6 * attempt)

    raise RuntimeError(f"NVD lookup failed after {retries} attempts: {last_error}")


def _pick_cvss(metrics: dict) -> dict | None:
    """Prefer CVSS v3.1 > v3.0 > v4.0 > v2, and NVD's own score over others."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData", {})
        return {
            "version": data.get("version", key[-2:]),
            "score": data.get("baseScore"),
            "severity": data.get("baseSeverity") or entry.get("baseSeverity"),
            "vector": data.get("vectorString", ""),
            "source": entry.get("source"),
        }
    return None


def explain_vector(vector: str) -> list[tuple[str, str]]:
    """'CVSS:3.1/AV:N/AC:L/...' -> [('Attack vector', 'Network (remote)'), ...]"""
    if not vector.startswith("CVSS:3"):
        return []
    out = []
    for part in vector.split("/")[1:]:
        key, _, val = part.partition(":")
        if key in VECTOR_LABELS:
            label, values = VECTOR_LABELS[key]
            out.append((label, values.get(val, val)))
    return out


def _affected(configurations: list, description: str = "", max_products: int = 200) -> list[dict]:
    """Turn CPE match data into [{'product': 'apache log4j', 'versions': ['>= 2.0.1, < 2.3.1']}]."""
    products: dict[str, list[str]] = {}
    for config in configurations or []:
        for node in config.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable"):
                    continue
                parts = m.get("criteria", "").split(":")
                if len(parts) < 6:
                    continue
                vendor, product, version = parts[3], parts[4], parts[5]
                update = parts[6] if len(parts) > 6 and parts[6] not in ("*", "-", "") else ""
                if update:
                    version = f"{version} {update}"  # e.g. "2.0 beta9"
                name = f"{vendor} {product}".replace("_", " ")
                bounds = []
                if m.get("versionStartIncluding"):
                    bounds.append(f">= {m['versionStartIncluding']}")
                if m.get("versionStartExcluding"):
                    bounds.append(f"> {m['versionStartExcluding']}")
                if m.get("versionEndIncluding"):
                    bounds.append(f"<= {m['versionEndIncluding']}")
                if m.get("versionEndExcluding"):
                    bounds.append(f"< {m['versionEndExcluding']}")
                if bounds:
                    rng = ", ".join(bounds)
                elif version not in ("*", "-", ""):
                    rng = version
                else:
                    rng = "all versions"
                versions = products.setdefault(name, [])
                if rng not in versions:
                    versions.append(rng)
    # Put the products the description actually talks about first. Big CVEs
    # (like Log4Shell) list dozens of downstream vendor products, and the
    # original vulnerable software would otherwise get buried.
    desc = description.lower()

    def mentioned(name: str) -> bool:
        product = name.split(" ", 1)[-1]
        return product in desc or product.replace(" ", "") in desc

    items = [{"product": p, "vendor": p.split(" ", 1)[0], "versions": v} for p, v in products.items()]
    items.sort(key=lambda a: not mentioned(a["product"]))  # stable: keeps NVD order otherwise
    return items[:max_products]


def _references(refs: list, limit: int = 6) -> list[dict]:
    def rank(r):
        tags = r.get("tags", [])
        return min((REF_PRIORITY.index(t) for t in tags if t in REF_PRIORITY), default=len(REF_PRIORITY))

    seen, unique = set(), []
    for r in refs or []:
        url = r.get("url", "").rstrip("/")
        if url and url not in seen:
            seen.add(url)
            unique.append(r)
    ranked = sorted(unique, key=rank)
    return [{"url": r["url"], "tags": r.get("tags", [])} for r in ranked[:limit]]


def parse(cve: dict) -> dict:
    """Flatten an NVD record into the fields kaidoku uses."""
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    cwes = sorted({
        d["value"]
        for w in cve.get("weaknesses", [])
        for d in w.get("description", [])
        if d.get("value", "").startswith("CWE-")
    })
    kev = None
    if cve.get("cisaExploitAdd"):
        kev = {
            "name": cve.get("cisaVulnerabilityName"),
            "date_added": cve.get("cisaExploitAdd"),
            "action_due": cve.get("cisaActionDue"),
            "required_action": cve.get("cisaRequiredAction"),
        }
    cvss = _pick_cvss(cve.get("metrics", {}))
    return {
        "id": cve.get("id"),
        "status": cve.get("vulnStatus"),
        "published": (cve.get("published") or "")[:10],
        "last_modified": (cve.get("lastModified") or "")[:10],
        "description": desc,
        "cvss": cvss,
        "vector_explained": explain_vector(cvss["vector"]) if cvss else [],
        "cwes": cwes,
        "kev": kev,
        "affected": _affected(cve.get("configurations", []), desc),
        "references": _references(cve.get("references", [])),
    }


def collect(cve_id: str) -> dict | None:
    raw = fetch(cve_id)
    return parse(raw) if raw else None
