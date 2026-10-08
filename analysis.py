"""
AI layer: Claude turns raw CVE data into a plain-English briefing.

Requires an Anthropic API key in the ANTHROPIC_API_KEY environment variable.
"""

import json
import os

SYSTEM_PROMPT = """You are a vulnerability analyst at 0x41, writing a short \
briefing about one CVE for a defender: an IT admin, security engineer, or \
business owner who needs to decide what to do. Be clear, practical, and \
defensive in focus. Explain jargon the first time you use it.

You get: the NVD record (description, CVSS, weakness/CWE, affected products, \
references), the EPSS score (probability of exploitation in the next 30 days), \
whether the CVE is on CISA's Known Exploited Vulnerabilities (KEV) list, and a \
rule-based urgency verdict. You may also get a description of the reader's \
environment.

Write Markdown with these sections:
## 1. What it is
2-4 sentences in plain English: what kind of flaw, in what software, and what \
an attacker gains.
## 2. How an attack works
Conceptual only: what an attacker needs (network access, credentials, a user \
clicking something) and what happens. Use the CVSS vector. Never provide \
exploit code, payloads, or step-by-step weaponization.
## 3. Who is affected
Affected products and versions, and how a reader can check whether they're \
exposed (e.g. how to find the installed version).
## 4. How urgent is it
Start this section with exactly one line that is one of: "### Critical", \
"### High", "### Medium", "### Low". Then explain using KEV, EPSS, and CVSS \
together. Agree with the rule-based verdict unless the data clearly argues \
otherwise, and say why if you differ.
## 5. What to do
Concrete steps: fixed versions or patches if the references or data indicate \
them, workarounds or mitigations, and what to monitor or log to detect attempts.
## 6. Business impact
What a successful attack could mean in practice (data exposure, downtime, \
ransomware foothold, etc). If an environment description is provided, tailor \
this to it, including whether it's likely affected at all.
## 7. Confidence and gaps
What the data doesn't tell us (e.g. NVD analysis pending, no EPSS score yet, \
vague description). Keep it short.

Formatting rules (the report is rendered in a terminal):
- Start directly with "## 1. What it is". No title line above it.
- Use "## " for the section headings exactly as above.
- Be concise: aim for 400-700 words.

Do not invent version numbers, patch names, or facts not supported by the \
data. If a fixed version isn't in the data, say to check the vendor advisory \
and point to the reference links. Hedge inferences ("likely", "suggests")."""


def pick_model(client) -> str:
    """Use $CLAUDE_MODEL if set, otherwise the newest Sonnet the API lists."""
    if os.environ.get("CLAUDE_MODEL"):
        return os.environ["CLAUDE_MODEL"]
    models = [m.id for m in client.models.list(limit=50)]  # newest first
    for mid in models:
        if "sonnet" in mid:
            return mid
    return models[0]


def explain(nvd: dict, epss: dict | None, verdict: dict, context: str | None = None) -> tuple[str, str]:
    """Send CVE data to Claude. Returns (markdown_briefing, model_used)."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise RuntimeError("ANTHROPIC_API_KEY is not set (see README for the API key step).")

    import anthropic  # imported here so lookups without --ai don't need it

    client = anthropic.Anthropic()
    model = pick_model(client)

    payload = {
        "nvd": {k: v for k, v in nvd.items() if k != "vector_explained"},
        "cvss_vector_plain_english": dict(nvd.get("vector_explained") or []),
        "epss": epss,
        "rule_based_verdict": verdict,
    }
    content = "CVE data (JSON):\n```json\n" + json.dumps(payload, indent=2) + "\n```"
    if context:
        content += f"\n\nReader's environment (tailor sections 4-6 to this):\n{context}"

    msg = client.messages.create(
        model=model,
        max_tokens=4000,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": content}],
    )
    text = "".join(block.text for block in msg.content if block.type == "text")
    if msg.stop_reason == "max_tokens":
        text += "\n\n> **Note:** this briefing hit the length limit and was cut off."
    return text, model
