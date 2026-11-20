"""
Preconditions (v0.10): what a CVE needs before an attack on it can work.

Kaidoku's verdicts are written for defenders ("PATCH NOW"). A bug bounty
hunter also needs to know whether a CVE is even reportable under a
program's rules: many programs exclude denial of service, and attacks that
need a man in the middle, a logged-in user, or a rare setup. Sorting that
out by hand means reading every CVE.

So each CVE gets a list of tags, each with where it came from:
- "cvss": read from the CVSS vector (v3.x or v4.0), e.g. PR:L means the
  attacker needs an account. Facts from the score, nothing guessed.
- "curated": from the small CURATED table below, for CVEs whose vector
  doesn't say what they need (e.g. CVE-2021-23017: "network, no auth" in
  the vector, but the attacker has to forge DNS answers to nginx's
  resolver, which in practice means sitting in the middle).

Tags never change the verdict or the ranking: "PATCH NOW" stays true for a
defender. --exclusions only marks CVEs as "likely not reportable here".
"""

# tag -> (short label for the table, sentence for the card and the AI)
TAGS = {
    "dos_only": ("DoS", "only affects availability: it can take the service down, not read or change data"),
    "needs_mitm": ("MITM", "the attacker has to sit between the client and the server (or forge network answers)"),
    "needs_auth": ("auth", "the attacker needs an account or other privileges first"),
    "needs_user_action": ("user", "a user has to do something (click a link, open a file) for it to work"),
    "needs_local_access": ("local", "the attacker must already be on the machine (local or physical access)"),
    "needs_adjacent_network": ("adj", "the attacker must be on the same network segment (Wi-Fi, LAN), not the internet"),
    "needs_specific_config": ("config", "it only works with a particular setup or setting turned on"),
}

# Program rule words (an --exclusions line) -> the tag they exclude.
EXCLUSION_CLASSES = {
    "dos": "dos_only",
    "mitm": "needs_mitm",
    "auth": "needs_auth",
    "user_action": "needs_user_action",
    "local": "needs_local_access",
    "adjacent": "needs_adjacent_network",
    "config": "needs_specific_config",
}

# CVEs whose vector doesn't show what they need. Each entry: the tags it
# adds and why, in plain words. Keep it short and only for CVEs we've seen
# misread; every entry must say why. Add freely, never guess.
CURATED = {
    "CVE-2023-44487": [("dos_only", "HTTP/2 Rapid Reset: floods the server with request resets; "
                                    "no data is read or changed")],
    "CVE-2021-23017": [("needs_mitm", "the attacker must forge DNS answers to nginx's own resolver, "
                                      "which needs a position on the DNS path")],
    "CVE-2021-3618": [("needs_mitm", "ALPACA: the attacker redirects TLS traffic from one server to "
                                     "another, so they must be on the network path")],
    "CVE-2025-23419": [("needs_specific_config", "only when TLS session resumption is on and several "
                                                 "server blocks share it, some requiring client certificates")],
}

# Weaknesses that are about exhausting resources: denial of service.
DOS_CWES = {"CWE-400", "CWE-770", "CWE-404", "CWE-674", "CWE-835", "CWE-1333"}


def _parts(vector: str) -> dict:
    """'CVSS:3.1/AV:N/PR:L/...' -> {'AV': 'N', 'PR': 'L', ...} (v3.x and v4.0 only)."""
    if not vector or not vector.startswith(("CVSS:3", "CVSS:4")):
        return {}
    out = {}
    for part in vector.split("/")[1:]:
        key, _, val = part.partition(":")
        out[key] = val
    return out


def _from_vector(p: dict) -> list[tuple[str, str]]:
    """Tags a CVSS v3.x / v4.0 vector backs up, each with the part that says so."""
    found = []
    if not p:
        return found
    v4 = "VC" in p
    no_data = (p.get("VC") == p.get("VI") == "N" and p.get("SC", "N") == p.get("SI", "N") == "N") if v4 \
        else (p.get("C") == p.get("I") == "N")
    hits_availability = (p.get("VA") in ("H", "L") or p.get("SA") in ("H", "L")) if v4 \
        else p.get("A") in ("H", "L")
    if no_data and hits_availability:
        found.append(("dos_only", "CVSS: no confidentiality or integrity impact, only availability"))
    if p.get("PR") in ("L", "H"):
        found.append(("needs_auth", f"CVSS: privileges required {'low' if p['PR'] == 'L' else 'high'} (PR:{p['PR']})"))
    if p.get("UI") in ("R", "P", "A"):
        found.append(("needs_user_action", f"CVSS: user interaction required (UI:{p['UI']})"))
    if p.get("AV") in ("L", "P"):
        found.append(("needs_local_access", f"CVSS: attack vector {'local' if p['AV'] == 'L' else 'physical'} "
                                            f"(AV:{p['AV']})"))
    elif p.get("AV") == "A":
        found.append(("needs_adjacent_network", "CVSS: attack vector adjacent network (AV:A)"))
    if p.get("AT") == "P":
        found.append(("needs_specific_config", "CVSS 4.0: attack requirements present (AT:P), "
                                               "conditions on the target must line up"))
    return found


def tags(record: dict) -> list[dict]:
    """Every precondition for one parsed NVD record, in TAGS order:
    [{"tag", "short", "label", "reason", "source": "cvss"|"cwe"|"curated"}].
    One entry per tag; a curated reason wins over the vector's (it's more specific)."""
    primary = _parts((record.get("cvss") or {}).get("vector", ""))
    v4 = _parts((record.get("cvss_v4") or {}).get("vector", ""))
    found = {}
    for tag, reason in _from_vector(primary):
        found[tag] = (reason, "cvss")
    # a v4.0 score next to the v3.x one can say more (AT:P has no v3 twin)
    for tag, reason in _from_vector(v4):
        if tag == "needs_specific_config":
            found.setdefault(tag, (reason, "cvss"))
    if not primary and set(record.get("cwes") or []) & DOS_CWES:
        cwe = sorted(set(record["cwes"]) & DOS_CWES)[0]
        found.setdefault("dos_only", (f"{cwe} is a resource-exhaustion weakness, and there's no "
                                      "CVSS vector to say otherwise", "cwe"))
    for tag, reason in CURATED.get((record.get("id") or "").upper(), []):
        found[tag] = (reason, "curated")
    return [{"tag": t, "short": TAGS[t][0], "label": TAGS[t][1], "reason": found[t][0],
             "source": found[t][1]} for t in TAGS if t in found]


def load_exclusions(path: str) -> list[str]:
    """--exclusions FILE: one class per line (dos, mitm, auth, user_action,
    local, adjacent, config), '#' comments. Returns the classes, in order.
    Raises ValueError for a file that can't be read or an unknown word, so
    nothing is looked up with rules that were mistyped."""
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError as e:
        raise ValueError(f"Couldn't read the exclusions file {path}: {e.strerror}")
    classes = []
    for n, line in enumerate(lines, 1):
        word = line.split("#")[0].strip().lower()
        if not word:
            continue
        if word not in EXCLUSION_CLASSES:
            raise ValueError(f"exclusions file line {n}: '{word}' isn't a class Kaidoku knows "
                             f"(use: {', '.join(EXCLUSION_CLASSES)})")
        if word not in classes:
            classes.append(word)
    if not classes:
        raise ValueError(f"the exclusions file {path} lists no classes")
    return classes


def excluded_by(pre: list[dict], exclusions: list[str] | None) -> list[str]:
    """The excluded classes this CVE falls under ([] = nothing excluded).
    Marks only: the CVE is never hidden and its verdict never changes."""
    if not exclusions:
        return []
    have = {p["tag"] for p in pre}
    return [c for c in exclusions if EXCLUSION_CLASSES[c] in have]
