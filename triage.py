"""
Rule-based urgency verdict. Works without AI.

Combines the three signals security teams actually use to prioritize:
- CISA KEV: is it being exploited in the wild right now? (strongest signal)
- EPSS: how likely is exploitation in the next 30 days?
- CVSS: how bad would it be if exploited?

This mirrors common risk-based patching guidance: KEV first, then high
EPSS, then high CVSS. It's a starting point, not a replacement for knowing
whether the affected software is actually in your environment.
"""


def verdict(nvd: dict, epss: dict | None) -> dict:
    score = (nvd.get("cvss") or {}).get("score") or 0
    prob = (epss or {}).get("probability") or 0

    if nvd.get("kev"):
        return {"level": "critical", "label": "PATCH NOW",
                "reason": f"Actively exploited in the wild (on CISA's KEV list since {nvd['kev']['date_added']})."}
    if not (nvd.get("cvss") or {}).get("score") and not epss:
        return {"level": "medium", "label": "NOT SCORED",
                "reason": "No CVSS or EPSS score yet, so urgency is unknown. Read the description and check the vendor advisory."}
    if prob >= 0.5 or (score >= 9 and prob >= 0.1):
        return {"level": "critical", "label": "PATCH NOW",
                "reason": f"Very likely to be exploited soon (EPSS {prob:.0%}) and/or critical severity."}
    if score >= 9 or prob >= 0.1 or (score >= 7 and prob >= 0.01):
        return {"level": "high", "label": "HIGH PRIORITY",
                "reason": "Severe and/or meaningfully likely to be exploited. Patch in your next cycle or sooner."}
    if score >= 7 or prob >= 0.01:
        return {"level": "medium", "label": "SCHEDULE",
                "reason": "Serious if exploited, but low exploitation activity so far."}
    return {"level": "low", "label": "ROUTINE",
            "reason": "Low severity and low likelihood of exploitation. Handle with normal patching."}


LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def rank_key(result: dict) -> tuple:
    """Sort key for a batch: most urgent first.

    Verdict level first, then KEV-listed before not, then higher EPSS,
    then higher CVSS. Python sorts tuples item by item, and smaller sorts
    first, so "bigger is worse" values are negated.
    """
    nvd = result["cve"]
    return (
        LEVEL_ORDER.get(result["verdict"]["level"], 9),
        0 if nvd.get("kev") else 1,
        -((result.get("epss") or {}).get("probability") or 0),
        -((nvd.get("cvss") or {}).get("score") or 0),
    )
