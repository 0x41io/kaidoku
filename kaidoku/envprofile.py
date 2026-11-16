"""
Environment profile: describe what you run once, and kaidoku uses it every time.

A profile is a small JSON file:
{
  "name": "acme-prod",
  "description": "Small business. Internet-facing Java apps on Tomcat behind nginx.",
  "software": ["apache tomcat", "apache log4j", "nginx", "fortinet fortios"]
}

kaidoku looks for ~/.kaidoku/profile.json unless you pass --profile FILE.
It lives in your home folder, not the repo, so it never gets committed.
"""

import json
import os

DEFAULT_PATH = os.path.join(os.path.expanduser("~"), ".kaidoku", "profile.json")


def load(path: str | None = None) -> dict | None:
    """Load and check a profile. Returns None when there's no profile to use.

    If you named a file with --profile and it's missing, that's an error.
    If the default file is missing, that's fine: you just don't have one yet.
    """
    explicit = path is not None
    path = os.path.expanduser(path or DEFAULT_PATH)

    if not os.path.exists(path):
        if explicit:
            raise ValueError(f"Profile not found: {path}")
        return None

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"{path} isn't valid JSON (line {e.lineno}, column {e.colno}): {e.msg}")
    except OSError as e:
        raise ValueError(f"Couldn't read {path}: {e.strerror}")

    if not isinstance(data, dict):
        raise ValueError(f"{path} should contain a JSON object {{...}}, not a {type(data).__name__}")

    description = data.get("description", "")
    software = data.get("software", [])
    if not isinstance(description, str):
        raise ValueError(f"{path}: \"description\" should be text")
    if not isinstance(software, list) or not all(isinstance(s, str) for s in software):
        raise ValueError(f"{path}: \"software\" should be a list of names, like [\"apache tomcat\", \"nginx\"]")

    return {
        "name": data.get("name") or os.path.basename(path),
        "description": description.strip(),
        "software": [s.strip().lower() for s in software if s.strip()],
        "path": path,
    }


def match(profile: dict | None, affected: list[dict]) -> dict | None:
    """Check a CVE's affected products against the software in your profile.

    Returns None if there's no profile (or it lists no software), otherwise:
      {"status": "match",   "products": ["apache tomcat"]}  # you run it
      {"status": "no",      "products": []}                 # nothing you listed
      {"status": "unknown", "products": []}                 # NVD hasn't listed products yet
    """
    if not profile or not profile["software"]:
        return None
    if not affected:
        return {"status": "unknown", "products": []}

    hits = []
    for a in affected:
        for name in profile["software"]:
            if _same_software(name, a["product"]):
                hits.append(a["product"])
                break  # one match is enough for this product
    return {"status": "match" if hits else "no", "products": hits}


def _same_software(name: str, product: str) -> bool:
    """Does your name appear as whole words inside the NVD product name?

    "tomcat"          vs "apache tomcat"             -> True
    "windows 11"      vs "microsoft windows 11 22h2" -> True
    "java"            vs "oracle javascript engine"  -> False (whole words only)
    """
    want = name.split()
    words = product.split()
    n = len(want)
    return any(words[i:i + n] == want for i in range(len(words) - n + 1))
