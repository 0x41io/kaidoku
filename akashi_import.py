"""
Read Akashi's proof history and turn it into findings Kaidoku can explain.

Akashi is 0x41's lead verifier: it proves or rules out Monomi's leads and
writes every verdict to an append-only history file, one JSON object per
line (<akashi folder>/history/<target>.jsonl). Kaidoku only READS that file.
It never imports Akashi and never changes a verdict: Akashi's code decided
it, Kaidoku explains it.

One lead can have several lines (verify, then a re-check after the fix).
They're grouped by the lead's stable "key", so the newest line is the lead's
status and the older ones are its timeline: confirmed -> fixed.
"""

import json

CONFIRMED, RULED_OUT, INCONCLUSIVE = "confirmed", "ruled_out", "inconclusive"
STATUSES = (CONFIRMED, RULED_OUT, INCONCLUSIVE)
REQUIRED = ("rule", "id", "status", "headline", "checked_at")

# Akashi's rule names, in plain words for the card and the AI
RULE_NAMES = {
    "takeover": "Subdomain takeover",
    "takeover_unknown": "Possible subdomain takeover",
    "email_spoofing": "Email spoofing",
    "around_cdn": "Origin reachable around the CDN",
}

# The state shown on the card, worked out from the history (not by the AI):
# label, badge level (Kaidoku's verdict colors), rank (most urgent first)
STATES = {
    "open": ("CONFIRMED", "critical", 0),
    "unclear": ("UNCLEAR", "medium", 1),
    "fixed": ("FIXED", "low", 2),
    "ruled_out": ("RULED OUT", "low", 3),
}


def rule_name(rule: str) -> str:
    return RULE_NAMES.get(rule, rule.replace("_", " ").capitalize())


def step_word(row: dict, before: list) -> str:
    """How one history line reads in the timeline. A ruled-out line after a
    confirmed one means the fix worked, so it reads "fixed"."""
    confirmed_before = any(b["status"] == CONFIRMED for b in before)
    if row["status"] == RULED_OUT and confirmed_before:
        return "fixed"
    if row["status"] == CONFIRMED and confirmed_before:
        return "still open"  # a re-check that found it again
    if row["status"] == INCONCLUSIVE and row.get("reason") == "origin_silent":
        return "unclear (likely firewalled)"
    return {CONFIRMED: "confirmed", RULED_OUT: "ruled out", INCONCLUSIVE: "unclear"}[row["status"]]


# What to do next for a lead that's still unclear, by Akashi's reason code.
# Worked out here, never by the AI. Unknown or missing reason -> the default.
NEXT_STEPS = {
    "origin_silent": ("set the origin's firewall to reject (not drop) direct traffic, then run "
                      "`akashi recheck`: a refused connection reads as fixed"),
}
DEFAULT_NEXT = "run `akashi recheck` again later, or check by hand using the proof below"


def next_step(lead: dict) -> str:
    """The next step for an unclear lead ('' for any other state)."""
    if lead["state"] != "unclear":
        return ""
    return NEXT_STEPS.get(lead["reason"], DEFAULT_NEXT)


def _state(rows: list) -> str:
    latest = rows[-1]["status"]
    if latest == CONFIRMED:
        return "open"
    if latest == INCONCLUSIVE:
        return "unclear"
    return "fixed" if any(r["status"] == CONFIRMED for r in rows[:-1]) else "ruled_out"


def _group_key(row: dict, rows: list) -> str:
    """Which lead a history line belongs to. Lines from Akashi v0.1.1 on carry
    a stable "key". Older lines don't: like Akashi's own recheck, they join
    the keyed lead with the same rule and id, when exactly one exists. If
    that's ambiguous (or there's none), they stay a lead of their own, never
    a guess."""
    if row.get("key"):
        return row["key"]
    keys = {r["key"] for r in rows
            if r.get("key") and r["rule"] == row["rule"] and r["id"] == row["id"]}
    return keys.pop() if len(keys) == 1 else f"{row['rule']}:{row['id']}"


def _check(row, n: int, path: str) -> dict:
    """One history line, or ValueError saying what's wrong with it."""
    if not isinstance(row, dict):
        raise ValueError(f"{path} line {n} isn't a JSON object (expected Akashi's proof history)")
    missing = [k for k in REQUIRED if k not in row]
    if missing:
        raise ValueError(f"{path} line {n} is missing {', '.join(missing)} "
                         "(expected Akashi's proof history: akashi/history/<target>.jsonl)")
    if row["status"] not in STATUSES:
        raise ValueError(f"{path} line {n} has an unknown status {row['status']!r}")
    for k in ("evidence", "fix"):
        if not isinstance(row.get(k, []), list):
            raise ValueError(f"{path} line {n}: {k} should be a list")
    return row


def load(path: str) -> tuple[str, list[dict]]:
    """Return (target, leads), leads ranked most urgent first.

    Each lead: rule, name, id, key, state, label, level, headline,
    evidence, fix, owner, reason, checked_at (all from its newest line),
    plus timeline: [{"word", "checked_at"}, ...] oldest first.
    """
    try:
        with open(path, encoding="utf-8") as f:
            lines = [(n, line) for n, line in enumerate(f, 1) if line.strip()]
    except OSError as e:
        raise ValueError(f"Couldn't read {path}: {e.strerror}")
    if not lines:
        raise ValueError(f"{path} is empty: run `akashi verify` first")

    rows = []
    for n, line in lines:
        try:
            rows.append(_check(json.loads(line), n, path))
        except json.JSONDecodeError:
            raise ValueError(f"{path} line {n} isn't valid JSON (expected Akashi's proof history)")

    targets = {r.get("target", "unknown target") for r in rows}
    if len(targets) > 1:
        raise ValueError(f"{path} mixes targets ({', '.join(sorted(targets))}); "
                         "Akashi writes one file per target")

    groups = {}
    for r in rows:  # file order is oldest first (Akashi only appends)
        groups.setdefault(_group_key(r, rows), []).append(r)

    leads = []
    for key, rs in groups.items():
        latest, state = rs[-1], _state(rs)
        label, level, rank = STATES[state]
        leads.append({
            "rule": latest["rule"], "name": rule_name(latest["rule"]), "id": latest["id"],
            "key": key, "state": state, "label": label, "level": level, "rank": rank,
            "headline": latest["headline"], "evidence": list(latest.get("evidence") or []),
            "fix": list(latest.get("fix") or []), "owner": latest.get("owner") or "",
            "reason": latest.get("reason") or "", "checked_at": latest["checked_at"],
            "timeline": [{"word": step_word(r, rs[:i]), "checked_at": r["checked_at"]}
                         for i, r in enumerate(rs)],
        })
    leads.sort(key=lambda d: (d["rank"], d["id"]))
    return targets.pop(), leads


def when(stamp: str) -> str:
    """'2026-11-15T17:02:09+00:00' -> '2026-11-15 17:02 UTC' (unchanged if odd)."""
    if len(stamp) >= 16 and stamp[10] == "T":
        return f"{stamp[:10]} {stamp[11:16]} UTC"
    return stamp
