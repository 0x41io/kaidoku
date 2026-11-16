"""
Where Kaidoku keeps its data: reports/ (saved AI briefings) and cache/ (the
CISA KEV catalog, refreshed every 24h). The same rule as monomi's home.py:

    1. the KAIDOKU_HOME environment variable, if it's set
    2. else the repo folder, when Kaidoku runs from a copy of the repo
       (`python kaidoku.py`, or `pip install -e .`): the same place as always
    3. else ~/.kaidoku (a plain `pip install`, so nothing is ever written
       inside Python's own package folder)

Each module builds its folder constants from this once, when it's imported.
"""

import os
import re

PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.dirname(PACKAGE_DIR)  # the folder above kaidoku/
ENV_VAR = "KAIDOKU_HOME"

# pyproject.toml's [project] name line. A plain text match rather than a TOML
# parser, because tomllib only exists from Python 3.11 and Kaidoku runs on 3.10.
_NAME_LINE = re.compile(r'^\s*name\s*=\s*"kaidoku"\s*$', re.MULTILINE)


def running_from_repo(folder: str = REPO_DIR) -> bool:
    """True if the folder above the kaidoku/ package is a copy of the Kaidoku repo.

    After a plain `pip install` the package sits in site-packages, where there's
    no pyproject.toml, so nothing there can make Kaidoku think it's in the repo.
    The name is checked too, so some other project's pyproject.toml doesn't count.
    """
    try:
        with open(os.path.join(folder, "pyproject.toml"), encoding="utf-8") as f:
            return bool(_NAME_LINE.search(f.read()))
    except OSError:
        return False


def where_data_lives() -> tuple[str, str]:
    """(data folder, why that one)."""
    chosen = os.environ.get(ENV_VAR, "").strip()
    if chosen:
        return os.path.abspath(os.path.expanduser(chosen)), f"{ENV_VAR} is set"
    if running_from_repo():
        return REPO_DIR, "running from the Kaidoku repo folder"
    return os.path.join(os.path.expanduser("~"), ".kaidoku"), "installed package, no repo folder"


def data_dir(*parts: str) -> str:
    """A path inside the data folder, e.g. data_dir("reports")."""
    return os.path.join(where_data_lives()[0], *parts)
