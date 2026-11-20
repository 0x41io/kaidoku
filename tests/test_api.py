"""
The contract with the 0x41 pipeline (v0.8): what kaidoku.api returns.

`0x41 run` will call these instead of the command line. If a change renames
or drops one of these keys, this fails before the pipeline breaks: add keys
freely, but renaming or removing one needs API_VERSION bumped and the
pipeline updated. NVD, EPSS, CISA KEV and Claude are all stubbed: no network.
"""

import sys
import types
from pathlib import Path

import pytest

from kaidoku import analysis, api
from kaidoku.sources import epss, kev, nvd

HISTORY = str(Path(__file__).parent / "fixtures" / "akashi-history.jsonl")
TOP = {"kaidoku_version", "api_version"}
LEAD_KEYS = {"rule", "name", "id", "key", "state", "label", "level", "headline",
             "evidence", "fix", "owner", "reason", "checked_at", "timeline"}
RESULT_KEYS = {"cve", "epss", "verdict", "stack", "found_on", "preconditions", "excluded_by"}


def fake_record(cve_id, score=9.8):
    return nvd.parse({"id": cve_id, "vulnStatus": "Analyzed", "published": "2026-01-01",
                      "descriptions": [{"lang": "en", "value": "test"}],
                      "metrics": {"cvssMetricV31": [{"source": "nvd", "type": "Primary", "cvssData": {
                          "version": "3.1", "baseScore": score, "baseSeverity": "CRITICAL",
                          "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}})


@pytest.fixture
def offline(monkeypatch):
    """NVD knows two CVEs; EPSS scores one; the KEV catalog is empty; no waiting."""
    known = {"CVE-2026-0001": fake_record("CVE-2026-0001", 9.8),
             "CVE-2026-0002": fake_record("CVE-2026-0002", 5.0)}
    monkeypatch.setattr(nvd, "collect", lambda cve_id: known.get(cve_id))
    monkeypatch.setattr(epss, "collect_many", lambda ids: {
        "CVE-2026-0002": {"probability": 0.5, "percentile": 0.99}})
    monkeypatch.setattr(kev, "load", lambda: ({}, "cache"))
    monkeypatch.setattr(api.time, "sleep", lambda s: None)


class FakeClient:
    def __init__(self):
        self.models = types.SimpleNamespace(
            list=lambda limit: [types.SimpleNamespace(id="claude-sonnet-test")])
        self.messages = types.SimpleNamespace(create=self.create)

    def create(self, *, model, max_tokens, system, messages):
        block = types.SimpleNamespace(type="text", text="## 1. What it is\nTest.")
        return types.SimpleNamespace(content=[block], stop_reason="end_turn")


@pytest.fixture
def fake_claude(monkeypatch):
    monkeypatch.setitem(sys.modules, "anthropic", types.SimpleNamespace(Anthropic=FakeClient))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(analysis, "_MODEL", None)


# ---------- explain_history ----------

def test_explain_history_contract(capsys):
    out = api.explain_history(HISTORY)
    assert set(out) == TOP | {"target", "leads"} and out["api_version"] == 1
    assert out["target"] == "origins" + ".test"
    assert all(LEAD_KEYS <= set(lead) for lead in out["leads"])
    assert [d["id"] for d in out["leads"]] == ["L1", "P1"]          # ranked, unclear first
    assert capsys.readouterr().out == ""                              # quiet: prints nothing


def test_explain_history_with_ai_adds_briefings(fake_claude):
    out = api.explain_history(HISTORY, ai=True)
    assert all(lead["briefing"].startswith("## 1.") and lead["model"] for lead in out["leads"])


def test_explain_history_ai_failure_is_kept_per_lead(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    out = api.explain_history(HISTORY, ai=True)
    assert all("ANTHROPIC_API_KEY" in lead["briefing_error"] for lead in out["leads"])
    assert all("briefing" not in lead for lead in out["leads"])


def test_explain_history_refuses_a_bad_file(tmp_path):
    bad = tmp_path / "x.jsonl"
    bad.write_text("not json\n", encoding="utf-8")
    with pytest.raises(ValueError, match="isn't valid JSON"):
        api.explain_history(str(bad))


# ---------- lookup_cves ----------

def test_lookup_cves_contract(offline, capsys):
    out = api.lookup_cves(["cve-2026-0001", "CVE-2026-0002", "CVE-2026-0001", "CVE-2026-9999"])
    assert set(out) == TOP | {"results", "missing", "warnings"}
    assert [r["cve"]["id"] for r in out["results"]] == ["CVE-2026-0002", "CVE-2026-0001"]  # EPSS 50% first
    assert all(RESULT_KEYS <= set(r) for r in out["results"])
    assert out["missing"] == ["CVE-2026-9999"] and out["warnings"] == []
    assert capsys.readouterr().out == ""


def test_lookup_cves_matches_the_command_line_shape(offline):
    r = api.lookup_cves(["CVE-2026-0001"])["results"][0]
    assert set(r["verdict"]) >= {"label", "level"} and r["cve"]["cvss"]["score"] == 9.8
    assert r["found_on"] == [] and "briefing" not in r


def test_lookup_cves_keeps_where_monomi_saw_it(offline):
    seen = [{"ip": "198.51.100.7", "hosts": ["www.example.test"]}]
    r = api.lookup_cves(["CVE-2026-0001"], found_on={"CVE-2026-0001": seen})["results"][0]
    assert r["found_on"] == seen


def test_lookup_cves_with_ai(offline, fake_claude):
    r = api.lookup_cves(["CVE-2026-0001"], ai=True)["results"][0]
    assert r["briefing"].startswith("## 1.") and r["model"] == "claude-sonnet-test"


def test_lookup_cves_reports_source_outages_as_warnings(offline, monkeypatch):
    def down(ids):
        raise RuntimeError("EPSS is down")
    monkeypatch.setattr(epss, "collect_many", down)
    monkeypatch.setattr(kev, "load", lambda: ({}, "stale"))
    out = api.lookup_cves(["CVE-2026-0001"])
    assert len(out["results"]) == 1
    assert any("EPSS unavailable" in w for w in out["warnings"])
    assert any("couldn't be refreshed" in w for w in out["warnings"])


def test_lookup_cves_nvd_errors_count_as_missing(offline, monkeypatch):
    def broken(cve_id):
        raise RuntimeError("NVD lookup failed after 3 attempts")
    monkeypatch.setattr(nvd, "collect", broken)
    out = api.lookup_cves(["CVE-2026-0001"])
    assert out["results"] == [] and out["missing"] == ["CVE-2026-0001"]
    assert "NVD lookup failed" in out["warnings"][0]


def test_lookup_cves_with_nothing_to_look_up(offline):
    assert api.lookup_cves(["", "  "])["results"] == []
