"""
First tests for kaidoku. Run them with:  python3 -m pytest -v
"""

import envprofile
import triage
from kaidoku import extract_ids





# --- extract_ids: finding CVE IDs in messy text ---

def test_extract_ids_finds_and_normalizes():
    text = "patch cve_2021_44228 and CVE-2024-3400 today"
    assert extract_ids(text) == ["CVE-2021-44228", "CVE-2024-3400"]


def test_extract_ids_removes_duplicates_in_order():
    text = "CVE-2024-3400, cve-2024-3400, CVE-2023-4966"
    assert extract_ids(text) == ["CVE-2024-3400", "CVE-2023-4966"]


def test_extract_ids_no_cves():
    assert extract_ids("nothing to see here") == []


    

# --- triage.verdict: the rule-based urgency call ---

def test_verdict_kev_is_always_patch_now():
    nvd = {"cvss": {"score": 3.1}, "kev": {"date_added": "2024-04-12", "ransomware": False}}
    assert triage.verdict(nvd, None)["label"] == "PATCH NOW"


def test_verdict_unscored():
    assert triage.verdict({}, None)["label"] == "NOT SCORED"


def test_verdict_high_epss_is_patch_now():
    nvd = {"cvss": {"score": 5.0}}
    assert triage.verdict(nvd, {"probability": 0.6})["label"] == "PATCH NOW"


def test_verdict_low_everything_is_routine():
    nvd = {"cvss": {"score": 3.0}}
    assert triage.verdict(nvd, {"probability": 0.001})["label"] == "ROUTINE"


 

# --- envprofile.match: is this CVE in your stack? ---

PROFILE = {"software": ["tomcat", "java"]}


def test_match_whole_word():
    result = envprofile.match(PROFILE, [{"product": "apache tomcat"}])
    assert result == {"status": "match", "products": ["apache tomcat"]}


def test_match_ignores_partial_words():
    result = envprofile.match(PROFILE, [{"product": "oracle javascript engine"}])
    assert result["status"] == "no"


def test_match_unknown_when_nvd_lists_nothing():
    assert envprofile.match(PROFILE, [])["status"] == "unknown"


def test_match_no_profile():
    assert envprofile.match(None, [{"product": "apache tomcat"}]) is None   