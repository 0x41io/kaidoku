"""
Terminal styling for kaidoku: the colored banner and status markers.

Uses plain ANSI escape codes (no extra dependency). Color turns itself off
when output isn't a terminal (piping to a file) or when NO_COLOR is set.
"""

import os
import re
import shutil
import sys

from kaidoku.sources import VERSION

ENABLED = sys.stdout.isatty() and "NO_COLOR" not in os.environ


def disable() -> None:
    global ENABLED
    ENABLED = False


def rgb(r: int, g: int, b: int) -> str:
    return f"\033[38;2;{r};{g};{b}m"


RESET = "\033[0m"
BOLD = "\033[1m"

WHITE = rgb(240, 240, 240)
RED = rgb(255, 40, 60)
GREY = rgb(130, 130, 140)
GREEN = rgb(80, 220, 120)
YELLOW = rgb(255, 200, 60)

def paint(text: str, *codes: str) -> str:
    return "".join(codes) + text + RESET if ENABLED else text

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def safe(text: str) -> str:
    """Neutralize control characters in untrusted text before printing it.

    NVD/CISA/Shodan text can contain escape codes that recolor, hide or
    rewrite lines in your terminal.
    """
    return _CONTROL.sub("?", str(text))


# "kaidoku" in the BlurVision ASCII font (figlet), lightest shade removed and letters spaced out
LOGO = [
    "▒▓█▓▒  ▒▓█▓▒   ▒▓██████▓▒   ▒▓█▓▒  ▒▓███████▓▒    ▒▓██████▓▒   ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒",
    "▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒",
    "▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒",
    "▒▓███████▓▒   ▒▓████████▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓███████▓▒   ▒▓█▓▒  ▒▓█▓▒",
    "▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒",
    "▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒",
    "▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓█▓▒  ▒▓███████▓▒    ▒▓██████▓▒   ▒▓█▓▒  ▒▓█▓▒   ▒▓██████▓▒",
]
LOGO_WIDTH = max(len(row) for row in LOGO)


def banner() -> str:
    """The big white "kaidoku" with "by Øx41 · version" under its right edge
    (white like monomi and akashi: the 0x41 brand is black and white).

    Terminals narrower than the logo get a one-line version instead,
    so the big one never wraps into a mess.
    """
    tag_text = f"by Øx41 · v{VERSION}"
    tag = paint("by ", GREY) + paint("Øx41", BOLD, WHITE) + paint(f" · v{VERSION}", GREY)

    cols = shutil.get_terminal_size((110, 24)).columns
    if cols <= LOGO_WIDTH:
        return f"\n{paint('kαidøku', BOLD, WHITE)}  {tag}\n"

    logo = "\n".join(paint(row, WHITE) for row in LOGO)
    pad = " " * (LOGO_WIDTH - len(tag_text))
    return f"\n{logo}\n{pad}{tag}\n"

# Status markers used throughout the CLI
def info(msg: str) -> None:
    print(f"{paint('[*]', GREY)} {msg}")


def good(msg: str) -> None:
    print(f"{paint('[+]', GREEN)} {msg}")


def warn(msg: str) -> None:
    print(f"{paint('[!]', YELLOW)} {msg}")


def fail(msg: str) -> None:
    print(f"{paint('[x]', BOLD, RED)} {msg}")


# ---------------------------------------------------------------------------
# AI report rendering
# ---------------------------------------------------------------------------

import re as _re

# Matches priority headers however the model writes them:
#   "### Critical", "### High", "### High priority", "**High**", "**Medium:**", "High priority:"
_PRIORITY = _re.compile(
    r"^[ \t]*(?:#{1,6}[ \t]*)?(?:\*\*|__)?[ \t]*(Critical|High|Medium|Low)(?![A-Za-z-])(?:[ \t]+priority)?"
    r"[ \t]*:?[ \t]*(?:\*\*|__)?[ \t]*:?[ \t]*$",
    _re.IGNORECASE | _re.MULTILINE,
)
_PRIORITY_STYLE = {"critical": "bold #ffffff on #8b0000", "high": "bold #ffffff on #c8102e", "medium": "bold #0c0c0c on #ffc83c", "low": "bold #ffffff on #5a5a64"}


# The AI briefing's look (v0.7.1): white headings, grey structure, like the
# white banner. Red stays only where it warns (the CRITICAL / HIGH badges,
# "in your stack", high EPSS), never as decoration.
REPORT_THEME = {
    "markdown.h1": "bold #f0f0f0",
    "markdown.h1.border": "#505058",
    "markdown.h2": "bold #f0f0f0",
    "markdown.h3": "bold #f0f0f0",
    "markdown.h4": "bold #f0f0f0",
    "markdown.strong": "bold #f0f0f0",
    "markdown.em": "italic #b4b4be",
    "markdown.code": "#c8c8d2",
    "markdown.item.bullet": "#8c8c96",
    "markdown.item.number": "#8c8c96",
    "markdown.block_quote": "#ffc83c",
    "markdown.hr": "#505058",
    "markdown.link": "#78b4ff",
    "markdown.table.border": "#505058",
    "markdown.table.header": "bold #f0f0f0",
}


def render_report(markdown: str) -> None:
    """Pretty-print the AI's Markdown report in the terminal.

    Uses the 'rich' library when it's installed (white headings and grey
    structure, matching the black-and-white 0x41 brand; real tables, bold text;
    Critical/High/Medium/Low keep their colored badges, since there color means
    something). Falls back to the raw Markdown when rich is missing or color is off.
    """
    try:
        from rich.console import Console
        from rich.markdown import Markdown
        from rich.text import Text
        from rich.theme import Theme
    except ImportError:
        print(markdown)
        return
    if not ENABLED:
        print(markdown)
        return

    console = Console(theme=Theme(REPORT_THEME), highlight=False)

    # rich centers top-level "# Title" headings; demote them so everything lines up left
    markdown = _re.sub(r"^# ", "## ", markdown, flags=_re.MULTILINE)

    # Split around Critical / High / Medium / Low headings so they can be drawn as badges
    pos = 0
    for m in _PRIORITY.finditer(markdown):
        chunk = markdown[pos:m.start()].strip()
        if chunk:
            console.print(Markdown(chunk, code_theme="monokai"))
        level = m.group(1).lower()
        console.print()
        console.print(Text(f" {level.upper()} ", style=_PRIORITY_STYLE[level]))
        pos = m.end()
    rest = markdown[pos:].strip()
    if rest:
        console.print(Markdown(rest, code_theme="monokai"))


# ---------------------------------------------------------------------------
# CVE summary card (plain ANSI, works without rich)
# ---------------------------------------------------------------------------

import shutil as _shutil
import textwrap as _textwrap

_SEV_COLOR = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW, "LOW": GREY}
_VERDICT_STYLE = {
    "critical": ("\033[1;38;2;255;255;255;48;2;139;0;0m", RED),
    "high": ("\033[1;38;2;255;255;255;48;2;200;16;46m", RED),
    "medium": ("\033[1;38;2;12;12;12;48;2;255;200;60m", YELLOW),
    "low": ("\033[1;38;2;255;255;255;48;2;90;90;100m", GREY),
}


def _cell(text: str, width: int) -> str:
    text = safe(text)
    return text if len(text) <= width else text[: width - 1] + "…"


def _badge(text: str, level: str) -> str:
    if not ENABLED:
        return f"[ {text} ]"
    return f"{_VERDICT_STYLE[level][0]} {text} {RESET}"


def _row(label: str, value: str, indent: str = "  ", width: int = 14) -> None:
    print(f"{indent}{paint(label.ljust(width), GREY)}{value}")


def _cols() -> int:
    return min(_shutil.get_terminal_size((100, 24)).columns, 120)


def _wrap(text: str, indent: str) -> str:
    width = max(40, _cols() - len(indent) - 2)
    return "\n".join(indent + line for line in _textwrap.wrap(safe(text), width))


def _cvss_row(cvss: dict) -> None:
    """One 'CVSS 3.1   8.1  HIGH   ████████░░' row."""
    sev = (cvss.get("severity") or "").upper()
    color = _SEV_COLOR.get(sev, WHITE)
    filled = max(0, min(10, round(cvss["score"])))
    bar = paint("█" * filled, color) + paint("░" * (10 - filled), GREY)
    score = f"{cvss['score']:.1f}"
    _row(f"CVSS {cvss['version']}", f"{paint(score, BOLD, color)}  {paint(sev.ljust(9), color)} {bar}")


def cve_card(nvd: dict, epss: dict | None, verdict: dict, stack: dict | None = None, found_on: list | None = None) -> None:
    title = paint(nvd["id"], BOLD, WHITE)
    if nvd.get("kev") and nvd["kev"].get("name"):
        title += paint("  ·  " + safe(nvd["kev"]["name"]), WHITE)
    print("  " + title)
    print("  " + paint("─" * 60, GREY))
    print(f"  {_badge(verdict['label'], verdict['level'])}  {verdict['reason']}")
    print()
    if stack:
        if stack["status"] == "match":
            names = ", ".join(stack["products"][:3])
            more = f" +{len(stack['products']) - 3} more" if len(stack["products"]) > 3 else ""
            _row("Your stack", paint("IN YOUR STACK", BOLD, RED) + f" · {names}{more}")
        elif stack["status"] == "no":
            _row("Your stack", paint("not listed", GREY) + paint(" (nothing in your profile matches by name)", GREY))
        else:
            _row("Your stack", paint("unknown", YELLOW) + paint(" (the NVD hasn't listed affected products yet)", GREY))
        print()

    if found_on:
        for i, loc in enumerate(found_on[:3]):
            hosts = safe(", ".join(loc["hosts"][:3])) or "no hostname"
            _row("Found on" if i == 0 else "", f"{paint(safe(loc['ip']), BOLD, WHITE)}  {hosts}")
        if len(found_on) > 3:
            _row("", paint(f"+{len(found_on) - 3} more IPs (full list with --json)", GREY))
        _row("", paint("(from monomi · Shodan InternetDB)", GREY))
        print()
    cvss = nvd.get("cvss")
    if cvss and cvss.get("score") is not None:
        _cvss_row(cvss)
        # v0.7.1: a v4.0 score next to the v3.x one, so the card matches what
        # vendors and advisories quote. The verdict still uses the line above.
        if (nvd.get("cvss_v4") or {}).get("score") is not None:
            _cvss_row(nvd["cvss_v4"])
    else:
        _row("CVSS", paint("not scored yet", GREY))

    if epss:
        p, pct = epss["probability"], epss["percentile"]
        color = RED if p >= 0.1 else YELLOW if p >= 0.01 else GREY
        prob = ">99.9%" if p >= 0.9995 else f"{p:.1%}" if p >= 0.01 else f"{p:.2%}"
        rank = f"(top {max(1 - pct, 0.001):.1%} of all CVEs)" if pct >= 0.9 else f"(riskier than {pct:.0%} of all CVEs)"
        _row("EPSS", f"{paint(prob, BOLD, color)} chance of exploitation in the next 30 days {paint(rank, GREY)}")
    else:
        _row("EPSS", paint("no score available", GREY))

    kev = nvd.get("kev")
    if kev:
        due = f" · US federal deadline {kev['action_due']}" if kev.get("action_due") else ""
        _row("CISA KEV", paint("YES", BOLD, RED) + f" · listed {kev['date_added']}{due}")
        if kev.get("ransomware"):
            _row("Ransomware", paint("KNOWN", BOLD, RED) + " · used in ransomware campaigns (per CISA)")
        elif kev.get("ransomware") is False:
            _row("Ransomware", paint("not known", GREY) + paint(" (no confirmed ransomware use)", GREY))
    else:
        _row("CISA KEV", paint("no", GREY) + paint(" (not on the known-exploited list)", GREY))

    if nvd.get("cwes"):
        _row("Weakness", ", ".join(nvd["cwes"]))
    _row("Published", f"{nvd.get('published', '?')}   {paint('status: ' + str(nvd.get('status')), GREY)}")

    if nvd.get("vector_explained"):
        print()
        print("  " + paint("How it can be attacked", BOLD, WHITE))
        for label, value in nvd["vector_explained"]:
            # Highlight the parts that make an attack easier or worse
            danger = (label in ("Attack vector",) and value.startswith("Network")) or \
                     (label in ("Privileges needed", "User interaction", "Attack requirements")
                      and value == "None") or \
                     (label == "Attack complexity" and value == "Low") or \
                     (label.endswith("impact") and value == "High")
            _row(label, paint(value, RED) if danger else value, indent="    ", width=26)

    if nvd.get("affected"):
        print()
        print("  " + paint("Affected", BOLD, WHITE))
        affected = nvd["affected"]
        shown = affected[:4]
        prod_w = min(max(len(a["product"]) for a in shown) + 2, 34)
        room = max(20, _cols() - 4 - prod_w)
        for a in shown:
            versions = a["versions"]
            text, used = "", 0
            for v in versions:
                piece = v if not text else " · " + v
                if len(text) + len(piece) > room - 10:
                    break
                text += piece
                used += 1
            more = paint(f" +{len(versions) - used} more", GREY) if used < len(versions) else ""
            print(f"    {_cell(a['product'], prod_w - 2).ljust(prod_w)}{text}{more}")
        rest = affected[len(shown):]
        if rest:
            from collections import Counter
            vendors = Counter(a["vendor"] for a in rest).most_common(4)
            summary = ", ".join(f"{v} {n}" for v, n in vendors)
            print("    " + paint(f"+ {len(rest)} more products ({summary}{', ...' if len(vendors) == 4 else ''}). Full list with --json", GREY))

    if nvd.get("description"):
        print()
        print("  " + paint("Description", BOLD, WHITE))
        print(_wrap(nvd["description"], "    "))

    if nvd.get("references"):
        print()
        print("  " + paint("References", BOLD, WHITE))
        for r in nvd["references"]:
            tags = r["tags"]
            tag = next((t for t in ("Patch", "Vendor Advisory", "Mitigation", "Exploit") if t in tags), None)
            tag = tag or (tags[0] if tags else "Link")
            print(f"    {paint(_cell('[' + tag + ']', 19).ljust(20), GREY)}{_cell(r['url'], max(30, _cols() - 26))}")


# ---------------------------------------------------------------------------
# Batch summary table (plain ANSI, works without rich)
# ---------------------------------------------------------------------------

_BADGE_W = len("HIGH PRIORITY")  # widest verdict label, so badges line up


def summary_table(results: list[dict], missing: list[str]) -> None:
    """One row per CVE, already sorted most-urgent first."""
    print("  " + paint(f"Triage summary · {len(results)} CVE{'s' if len(results) != 1 else ''}, most urgent first", BOLD, WHITE))
    print("  " + paint("─" * 60, GREY))

    badge_w = _BADGE_W + (2 if ENABLED else 4)  # " LABEL " in color, "[ LABEL ]" without
    has_stack = any(r.get("stack") for r in results)  # only show the column when a profile is in use
    has_found = any(r.get("found_on") for r in results)  # only when CVEs came from monomi
    found_w = 30
    found_head = f"{'Found on'.ljust(found_w)}  " if has_found else ""
    stack_head = f"{'Stack':<5}  " if has_stack else ""
    head = f"  {'#':>3}  {'CVE'.ljust(16)} {'Verdict'.ljust(badge_w)}  {'CVSS':>4}  {'EPSS':>6}  {'KEV':<3}  {'Ransom':<6}  {stack_head}{found_head}Product"
    print(paint(head, GREY))

    prod_room = max(16, _cols() - len(head) + len("Product"))
    for n, r in enumerate(results, 1):
        nvd, epss, v = r["cve"], r.get("epss"), r["verdict"]

        badge = _badge(v["label"].center(_BADGE_W), v["level"])

        cvss = nvd.get("cvss") or {}
        if cvss.get("score") is not None:
            sev = (cvss.get("severity") or "").upper()
            cvss_txt = paint(f"{cvss['score']:>4.1f}", _SEV_COLOR.get(sev, WHITE))
        else:
            cvss_txt = paint("   -", GREY)

        if epss:
            p = epss["probability"]
            color = RED if p >= 0.1 else YELLOW if p >= 0.01 else GREY
            prob = ">99.9%" if p >= 0.9995 else f"{p:.1%}" if p >= 0.01 else f"{p:.2%}"
            epss_txt = paint(prob.rjust(6), color)
        else:
            epss_txt = paint("     -", GREY)

        kev = nvd.get("kev") or {}
        kev_txt = paint("YES", BOLD, RED) if kev else paint("no ", GREY)
        ransom_txt = paint("KNOWN ", BOLD, RED) if kev.get("ransomware") else paint("-     ", GREY)
        stack_txt = ""
        if has_stack:
            status = (r.get("stack") or {}).get("status")
            if status == "match":
                stack_txt = paint("YES  ", BOLD, RED) + "  "
            elif status == "unknown":
                stack_txt = paint("?    ", YELLOW) + "  "
            else:
                stack_txt = paint("-    ", GREY) + "  "
        found_txt = ""
        if has_found:
            locs = r.get("found_on") or []
            if locs:
                where = locs[0]["hosts"][0] if locs[0]["hosts"] else locs[0]["ip"]
                if len(locs) > 1:
                    where += f" (+{len(locs) - 1})"
                found_txt = _cell(where, found_w).ljust(found_w) + "  "
            else:
                found_txt = paint("-".ljust(found_w), GREY) + "  "
        affected = nvd.get("affected") or []
        product = affected[0]["product"] if affected else "-"
        if len(affected) > 1:
            product += f" (+{len(affected) - 1})"

        print(f"  {n:>3}  {nvd['id'].ljust(16)} {badge}  {cvss_txt}  {epss_txt}  {kev_txt}  {ransom_txt}  {stack_txt}{found_txt}{_cell(product, prod_room)}")

    if missing:
        print()
        warn("Not found or failed: " + ", ".join(missing))


# ---------------------------------------------------------------------------
# Akashi findings (v0.7): proven leads, explained
# ---------------------------------------------------------------------------

def _row_wrapped(label: str, text: str, width: int = 14) -> None:
    """Like _row, but long text wraps and lines up under the value column."""
    indent = "  " + " " * width
    lines = _wrap(text, indent).split("\n")
    print(f"  {paint(label.ljust(width), GREY)}{lines[0].lstrip()}")
    for line in lines[1:]:
        print(line)


def finding_card(lead: dict) -> None:
    """One lead from Akashi's proof history: its state, the proof, the fix,
    and how it got here. Everything comes from Akashi's verdicts; nothing is
    decided here. Hostnames and DNS answers come from the target, so every
    line goes through safe()."""
    from kaidoku.akashi_import import next_step, when

    print("  " + paint(f"{lead['id']}  {lead['name']}", BOLD, WHITE))
    print("  " + paint("─" * 60, GREY))
    print(f"  {_badge(lead['label'], lead['level'])}  {safe(lead['headline'])}")
    print()
    steps = [f"{t['word']} {paint(when(t['checked_at']), GREY)}" for t in lead["timeline"]]
    _row("History", " → ".join(steps))
    for i, line in enumerate(lead["evidence"]):
        _row_wrapped("Proof" if i == 0 else "", line)
    if next_step(lead):
        _row_wrapped("Next", next_step(lead))
    if lead["fix"] and lead["state"] == "open":
        print()
        owner = f" ({safe(lead['owner'])})" if lead["owner"] else ""
        _row("Fix" + owner, "")
        width = max(40, _cols() - 6)
        for n, step in enumerate(lead["fix"], 1):
            # hanging indent: wrapped lines line up under the step's text, not its number
            lines = _textwrap.wrap(safe(step), width, initial_indent=f"    {n}. ",
                                   subsequent_indent=" " * (len(str(n)) + 6))
            print("\n".join(lines))
    elif lead["state"] == "fixed":
        _row("Fix", paint("closed: the re-check no longer finds it", GREEN))
    _row("", paint("(from akashi · proof history)", GREY))


def findings_table(leads: list[dict]) -> None:
    """One row per lead, already ranked: still open first, then unclear,
    fixed, ruled out."""
    print("  " + paint(f"Findings · {len(leads)} lead{'s' if len(leads) != 1 else ''}, "
                       "most urgent first", BOLD, WHITE))
    print("  " + paint("─" * 60, GREY))
    w = len("RULED OUT")
    print(paint(f"  {'ID':<4}  {'State'.ljust(w + (2 if ENABLED else 4))}  {'Finding'.ljust(32)}  Headline", GREY))
    room = max(20, _cols() - 4 - 2 - (w + 4) - 2 - 32 - 2)
    for lead in leads:
        badge = _badge(lead["label"].center(w), lead["level"])
        print(f"  {lead['id']:<4}  {badge}  {_cell(lead['name'], 32).ljust(32)}  {_cell(lead['headline'], room)}")
