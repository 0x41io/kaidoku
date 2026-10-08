"""
Terminal styling for kaidoku: the colored banner and status markers.

Uses plain ANSI escape codes (no extra dependency). Color turns itself off
when output isn't a terminal (piping to a file) or when NO_COLOR is set.
"""

import os
import sys

from sources import VERSION

ENABLED = sys.stdout.isatty() and "NO_COLOR" not in os.environ


def disable() -> None:
    global ENABLED
    ENABLED = False


def rgb(r: int, g: int, b: int) -> str:
    return f"\033[38;2;{r};{g};{b}m"


RESET = "\033[0m"
BOLD = "\033[1m"

WHITE = rgb(240, 240, 240)
SILVER = rgb(120, 120, 128)    # shadow edge on the white letters
RED = rgb(255, 40, 60)
DARK_RED = rgb(110, 0, 18)     # shadow edge on the red letters
GREY = rgb(130, 130, 140)
GREEN = rgb(80, 220, 120)
YELLOW = rgb(255, 200, 60)

# Top-to-bottom red gradient for the "41" (bright at the top, deeper below)
RED_RAMP = [rgb(255, 70, 85), rgb(255, 45, 62), rgb(235, 25, 45),
            rgb(210, 15, 35), rgb(180, 8, 28), rgb(150, 0, 22)]


def paint(text: str, *codes: str) -> str:
    return "".join(codes) + text + RESET if ENABLED else text


LOGO = [
    " ██████╗ ██╗  ██╗██╗  ██╗ ██╗",
    "██╔═████╗╚██╗██╔╝██║  ██║███║",
    "██║██╔██║ ╚███╔╝ ███████║╚██║",
    "████╔╝██║ ██╔██╗ ╚════██║ ██║",
    "╚██████╔╝██╔╝ ██╗     ██║ ██║",
    " ╚═════╝ ╚═╝  ╚═╝     ╚═╝ ╚═╝",
]
SPLIT = 17  # column where "0x" ends and "41" begins


def _shade(segment: str, face: str, edge: str) -> str:
    """Solid blocks get the face color, box-drawing 'shadow' gets the edge color."""
    out, current = [], None
    for ch in segment:
        color = face if ch == "█" else edge if ch.strip() else None
        if color and color != current:
            out.append(color)
            current = color
        out.append(ch)
    return "".join(out) + RESET


def banner() -> str:
    side = [
        "",
        f"{paint('kαidøku', BOLD, RED)}  {paint('v' + VERSION, GREY)}",
        "",
        paint("CVE intel · AI explained", GREY),
        paint("by ", GREY) + paint("0x", WHITE) + paint("41", RED),
        "",
    ]
    lines = []
    for i, row in enumerate(LOGO):
        if ENABLED:
            logo = _shade(row[:SPLIT], WHITE, SILVER) + _shade(row[SPLIT:], RED_RAMP[i], DARK_RED)
        else:
            logo = row
        lines.append(f"{logo}   {side[i]}".rstrip())
    return "\n" + "\n".join(lines) + "\n"


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


def render_report(markdown: str) -> None:
    """Pretty-print the AI's Markdown report in the terminal.

    Uses the 'rich' library when it's installed (headings in 0x41 red, real
    tables, bold text, Critical/High/Medium/Low as colored badges). Falls back to the
    raw Markdown when rich is missing or color is off.
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

    theme = Theme({
        "markdown.h1": "bold #ff283c",
        "markdown.h1.border": "#6e0012",
        "markdown.h2": "bold #ff283c",
        "markdown.h3": "bold #f0f0f0",
        "markdown.h4": "bold #f0f0f0",
        "markdown.strong": "bold #f0f0f0",
        "markdown.em": "italic #b4b4be",
        "markdown.code": "#ff8c96",
        "markdown.item.bullet": "#ff283c",
        "markdown.item.number": "#ff283c",
        "markdown.block_quote": "#ffc83c",
        "markdown.hr": "#6e0012",
        "markdown.link": "#78b4ff",
        "markdown.table.border": "#6e0012",
        "markdown.table.header": "bold #ff283c",
    })
    console = Console(theme=theme, highlight=False)

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
    return "\n".join(indent + line for line in _textwrap.wrap(text, width))


def cve_card(nvd: dict, epss: dict | None, verdict: dict) -> None:
    title = paint(nvd["id"], BOLD, WHITE)
    if nvd.get("kev") and nvd["kev"].get("name"):
        title += paint("  ·  " + nvd["kev"]["name"], WHITE)
    print("  " + title)
    print("  " + paint("─" * 60, GREY))
    print(f"  {_badge(verdict['label'], verdict['level'])}  {verdict['reason']}")
    print()

    cvss = nvd.get("cvss")
    if cvss and cvss.get("score") is not None:
        sev = (cvss.get("severity") or "").upper()
        color = _SEV_COLOR.get(sev, WHITE)
        filled = round(cvss["score"])
        bar = paint("█" * filled, color) + paint("░" * (10 - filled), GREY)
        score = f"{cvss['score']:.1f}"
        _row(f"CVSS {cvss['version']}", f"{paint(score, BOLD, color)}  {paint(sev.ljust(9), color)} {bar}")
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
                     (label in ("Privileges needed", "User interaction") and value == "None") or \
                     (label == "Attack complexity" and value == "Low") or \
                     (label.endswith("impact") and value == "High")
            _row(label, paint(value, RED) if danger else value, indent="    ", width=24)

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
