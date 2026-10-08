# kaidøku

```
 ██████╗ ██╗  ██╗██╗  ██╗ ██╗
██╔═████╗╚██╗██╔╝██║  ██║███║
██║██╔██║ ╚███╔╝ ███████║╚██║
████╔╝██║ ██╔██╗ ╚════██║ ██║
╚██████╔╝██╔╝ ██╗     ██║ ██║
 ╚═════╝ ╚═╝  ╚═╝     ╚═╝ ╚═╝   kαidøku
```

**kaidoku** by 0x41: **CVE intelligence, explained.**

*Kaidoku (解読) is Japanese for "decipher".* Give it a CVE ID and it pulls the official data, tells you how urgent it really is, and (optionally) has Claude explain it in plain English: what it is, how an attack works, who's affected, and what to do.

Most CVE pages give you a wall of text and a CVSS number. kaidoku combines the three signals security teams actually use to prioritize:

| Signal | Question it answers | Source |
|---|---|---|
| **CISA KEV** | Is it being exploited in the wild right now? | NVD (CISA fields) |
| **EPSS** | How likely is exploitation in the next 30 days? | [FIRST.org](https://www.first.org/epss/) |
| **CVSS** | How bad would it be if exploited? | [NVD](https://nvd.nist.gov/) |

---

## Features

- **CVE summary card:** severity, exploitation likelihood, known-exploited status, weakness type, affected products and versions, and the most useful reference links (patches and advisories first)
- **Urgency verdict without AI:** `PATCH NOW` / `HIGH PRIORITY` / `SCHEDULE` / `ROUTINE`, based on KEV first, then EPSS, then CVSS
- **Attack vector in plain English:** `AV:N/AC:L/PR:N` becomes "Network (remote) · Low complexity · No privileges needed", with the dangerous parts highlighted
- **AI briefing (optional, `--ai`):** Claude explains what it is, how an attack works (conceptually, never exploit code), who's affected, how urgent it is, what to do, and the business impact
- **Tailored impact (`--context`):** describe your environment and the briefing tells you what it means for *you*
- **Several CVEs at once:** pass multiple IDs
- **Saved briefings** in `reports/`, and **JSON export**
- No API keys needed for lookups

## Installation

Requires Python 3.10+.

```bash
git clone https://github.com/0x41io/kaidoku.git
cd kaidoku
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### API keys (both optional)

**Claude** (only for `--ai`): get a key at [console.anthropic.com](https://console.anthropic.com).

```bash
export ANTHROPIC_API_KEY="your-key-here"
export CLAUDE_MODEL="model-id-here"   # optional; defaults to the newest Sonnet
```

**NVD** (only if you look up a lot of CVEs): without a key the NVD allows about 5 lookups per 30 seconds. A [free NVD key](https://nvd.nist.gov/developers/request-an-api-key) raises that to 50.

```bash
export NVD_API_KEY="your-key-here"
```

Never commit your keys. kaidoku reads them from the environment only.

## Usage

```bash
# Summary card + urgency verdict (no keys needed)
python kaidoku.py CVE-2021-44228

# Add a plain-English AI briefing (saved to reports/)
python kaidoku.py CVE-2021-44228 --ai

# Tailor the briefing to your environment
python kaidoku.py CVE-2021-44228 --ai --context "Small business, Java web apps on Tomcat, internet-facing"

# Several CVEs, saved as JSON
python kaidoku.py CVE-2024-3400 CVE-2023-4966 --json results.json

# Plain output (also honors NO_COLOR)
python kaidoku.py CVE-2021-44228 --no-color
```

### Example card

```
  CVE-2021-44228  ·  Apache Log4j2 Remote Code Execution Vulnerability
  ────────────────────────────────────────────────────────────
  [ PATCH NOW ]  Actively exploited in the wild (on CISA's KEV list since 2021-12-10).

  CVSS 3.1      10.0  CRITICAL  ██████████
  EPSS          94.4% chance of exploitation in the next 30 days (top 0.1% of all CVEs)
  CISA KEV      YES · exploited in the wild · added 2021-12-10 · federal patch deadline 2021-12-24
  Weakness      CWE-20, CWE-400, CWE-502, CWE-917

  How it can be attacked
    Attack vector           Network (remote)
    Attack complexity       Low
    Privileges needed       None
    User interaction        None
    ...
```

## How it works

```
CVE ID ──► NVD API ───────► CVSS, KEV status, CWE, products, references ─┐
       └─► FIRST EPSS API ─► exploitation probability ────────────────────┤
                                                                          ├─► urgency verdict ─► summary card
                                                                          └─► Claude (--ai) ───► briefing + reports/
```

## Project structure

```
kaidoku/
├── kaidoku.py            # CLI entry point
├── triage.py             # rule-based urgency verdict (KEV > EPSS > CVSS)
├── analysis.py           # Claude briefing
├── ui.py                 # banner, summary card, report rendering
├── sources/
│   ├── nvd.py            # NVD API 2.0 (+ CISA KEV fields)
│   └── epss.py           # FIRST EPSS API
├── reports/              # saved briefings (git-ignored)
└── requirements.txt
```

## Limitations

- The urgency verdict is a starting point. What matters most is whether the affected software is actually in your environment.
- New CVEs are often "Awaiting Analysis" in the NVD, with no CVSS score or product list yet.
- EPSS scores update daily and aren't available for every CVE.
- AI briefings are only as good as the public data. Always confirm fixed versions in the vendor's advisory.

## Roadmap

- [ ] Read CVEs from vulnerability scanner exports (Nessus, OpenVAS, Trivy)
- [ ] Environment profiles saved to a file instead of `--context` every time
- [ ] Web UI with PDF report export

## License

MIT. See [LICENSE](LICENSE).

---

Built by **0x41**. See also [mønømi](https://github.com/0x41io/monomi), passive domain recon with AI analysis.
