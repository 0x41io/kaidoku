#!/usr/bin/env python3
"""
Runs the kaidoku command line: python kaidoku.py CVE-2021-44228

The code lives in the kaidoku/ package (kaidoku/cli.py). This file stays at
the repo root so existing commands keep working. Python picks the kaidoku/
folder over this file when the code below says "from kaidoku", so the two
don't clash.
"""

import sys

from kaidoku.cli import main

if __name__ == "__main__":
    sys.exit(main())
