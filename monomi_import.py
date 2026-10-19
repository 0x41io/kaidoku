"""
Read a monomi --json results file and pull out its CVEs, keeping where each
one was found (IP + hostnames). monomi is 0x41's recon tool; its --ports
option looks up open ports and CVEs per IP in Shodan InternetDB.
"""

import json


def load(path: str) -> tuple[str, list[str], dict[str, list[dict]]]:
    """Return (target, cve_ids, found_on).

    found_on maps each CVE to where monomi saw it:
    {'CVE-2023-44487': [{'ip': '34.246.45.89', 'hosts': ['app.example.com']}], ...}
    CDN edge IPs are skipped: their CVEs belong to the CDN, not the target.
    """
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except OSError as e:
        raise ValueError(f"Couldn't read {path}: {e.strerror}")
    except json.JSONDecodeError:
        raise ValueError(f"{path} isn't valid JSON (expected a monomi --json file)")

    exposure = data.get("exposure") if isinstance(data, dict) else None
    if not exposure:
        raise ValueError(f"{path} has no port/CVE data. Run monomi with --ports --json to create one.")

    found_on = {}
    for ip, d in exposure.get("ips", {}).items():
        if d.get("shared_edge"):
            continue
        for cve in d.get("vulns", []):
            found_on.setdefault(cve.upper(), []).append({"ip": ip, "hosts": d.get("hosts", [])})
    return data.get("target", "unknown target"), list(found_on), found_on
