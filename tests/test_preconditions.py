"""
Preconditions (v0.10): what a CVE needs before an attack on it can work,
from the CVSS vector plus a small curated list, and --exclusions marking
(never hiding) CVEs a bug bounty program won't take.

Run with:  python3 -m pytest -v
"""

import json
import sys
import types

import pytest

from kaidoku import analysis, api, cli, preconditions, ui
from kaidoku.sources import epss, kev, nvd


def rec(vector, cve_id="CVE-2026-0001", v4=None, cwes=None):
    """A parsed record with just what preconditions.tags() reads."""
    return {"id": cve_id, "cvss": {"vector": vector} if vector else None,
            "cvss_v4": {"vector": v4} if v4 else None, "cwes": cwes or []}


def tags(r):
    return [p["tag"] for p in preconditions.tags(r)]


def test_network_no_auth_no_user_needs_nothing():
    assert tags(rec("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")) == []


def test_availability_only_is_dos():
    t = preconditions.tags(rec("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"))
    assert [p["tag"] for p in t] == ["dos_only"] and t[0]["source"] == "cvss" and t[0]["short"] == "DoS"


def test_some_data_impact_is_not_dos_only():
    assert "dos_only" not in tags(rec("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H"))


@pytest.mark.parametrize("part, tag", [
    ("PR:L", "needs_auth"), ("PR:H", "needs_auth"), ("UI:R", "needs_user_action"),
    ("AV:L", "needs_local_access"), ("AV:P", "needs_local_access"), ("AV:A", "needs_adjacent_network")])
def test_each_v3_part_gives_its_tag(part, tag):
    base = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"}
    key, val = part.split(":")
    base[key] = val
    vector = "CVSS:3.1/" + "/".join(f"{k}:{v}" for k, v in base.items())
    assert tags(rec(vector)) == [tag]


def test_adjacent_network_is_not_called_mitm():
    assert "needs_mitm" not in tags(rec("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))


def test_v4_vector_user_action_dos_and_attack_requirements():
    assert tags(rec("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N")) == [
        "dos_only", "needs_user_action", "needs_specific_config"]


def test_v4_next_to_v31_only_adds_attack_requirements():
    t = tags(rec("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                 v4="CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"))
    assert t == ["needs_specific_config"]   # the v3.1 score is the one the verdict uses


def test_resource_exhaustion_cwe_is_dos_only_without_a_vector():
    t = preconditions.tags(rec(None, cwes=["CWE-400"]))
    assert [p["tag"] for p in t] == ["dos_only"] and t[0]["source"] == "cwe"
    # with a vector, the vector decides
    assert tags(rec("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cwes=["CWE-400"])) == []


def test_v2_vectors_are_left_alone():
    assert tags(rec("AV:N/AC:L/Au:N/C:P/I:P/A:P")) == []


@pytest.mark.parametrize("cve_id, tag", [
    ("CVE-2023-44487", "dos_only"), ("CVE-2021-23017", "needs_mitm"),
    ("CVE-2021-3618", "needs_mitm"), ("CVE-2025-23419", "needs_specific_config")])
def test_curated_cves_get_their_tag_with_a_reason(cve_id, tag):
    t = {p["tag"]: p for p in preconditions.tags(rec("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                                     cve_id=cve_id))}
    assert t[tag]["source"] == "curated" and len(t[tag]["reason"]) > 20


def test_every_curated_entry_has_a_known_tag_and_a_reason():
    for cve_id, entries in preconditions.CURATED.items():
        assert cve_id.startswith("CVE-")
        for tag, reason in entries:
            assert tag in preconditions.TAGS and reason


def test_tags_come_out_in_one_fixed_order():
    t = tags(rec("CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:H"))
    assert t == ["dos_only", "needs_auth", "needs_user_action", "needs_local_access"]


# ---------- --exclusions ----------

def write(tmp_path, text):
    p = tmp_path / "exclusions.txt"
    p.write_text(text)
    return str(p)


def test_exclusions_file_is_read_with_comments_and_dupes(tmp_path):
    assert preconditions.load_exclusions(write(tmp_path, "# program rules\nDoS\nmitm  # no MITM\ndos\n")) == [
        "dos", "mitm"]


@pytest.mark.parametrize("text, why", [("denial\n", "isn't a class"), ("# nothing\n", "lists no classes")])
def test_bad_exclusions_files_are_refused(tmp_path, text, why):
    with pytest.raises(ValueError, match=why):
        preconditions.load_exclusions(write(tmp_path, text))


def test_missing_exclusions_file_is_refused(tmp_path):
    with pytest.raises(ValueError, match="Couldn't read"):
        preconditions.load_exclusions(str(tmp_path / "nope.txt"))


def test_excluded_by_marks_only_matching_classes():
    pre = preconditions.tags(rec("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"))   # DoS + auth
    assert preconditions.excluded_by(pre, ["dos", "mitm"]) == ["dos"]
    assert preconditions.excluded_by(pre, ["mitm"]) == []
    assert preconditions.excluded_by(pre, None) == []


# ---------- where they show up ----------

def parsed(cve_id, vector):
    return nvd.parse({"id": cve_id, "vulnStatus": "Analyzed", "published": "2026-01-01",
                      "descriptions": [{"lang": "en", "value": "test"}],
                      "metrics": {"cvssMetricV31": [{"source": "nvd", "type": "Primary", "cvssData": {
                          "version": "3.1", "baseScore": 7.5, "baseSeverity": "HIGH",
                          "vectorString": vector}}]}})


DOS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
RCE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_card_shows_needs_and_the_bug_bounty_line(capsys):
    r = parsed("CVE-2023-44487", DOS)
    pre = preconditions.tags(r)
    ui.cve_card(r, None, {"level": "high", "label": "HIGH PRIORITY", "reason": "x"}, None, None,
                pre, ["dos"])
    out = capsys.readouterr().out
    assert "Needs" in out and "DoS" in out and "Rapid Reset" in out   # curated: its own reason
    assert "only affects availability" not in out
    assert "likely not reportable here" in out and "dos" in out


def test_card_shows_the_general_label_and_vector_part_for_cvss_tags(capsys):
    r = parsed("CVE-2026-0002", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
    ui.cve_card(r, None, {"level": "high", "label": "HIGH PRIORITY", "reason": "x"}, None, None,
                preconditions.tags(r))
    out = capsys.readouterr().out
    assert "needs an account or other privileges" in out and "PR:L" in out
    assert "Bug bounty" not in out


def test_card_without_preconditions_has_no_needs_row(capsys):
    r = parsed("CVE-2026-0001", RCE)
    ui.cve_card(r, None, {"level": "high", "label": "HIGH PRIORITY", "reason": "x"})
    assert "Needs" not in capsys.readouterr().out


def row(r, pre, excluded):
    return {"cve": r, "epss": None, "verdict": {"level": "high", "label": "HIGH PRIORITY"},
            "stack": None, "found_on": [], "preconditions": pre, "excluded_by": excluded}


def test_table_has_a_needs_column_with_a_mark_for_excluded(capsys, monkeypatch):
    monkeypatch.setattr(ui, "ENABLED", False)   # plain text, only for this test
    a, b = parsed("CVE-2023-44487", DOS), parsed("CVE-2026-0001", RCE)
    ui.summary_table([row(a, preconditions.tags(a), ["dos"]), row(b, [], [])], [])
    out = capsys.readouterr().out
    assert "Needs" in out and "DoS*" in out


def test_table_without_any_preconditions_has_no_needs_column(capsys):
    b = parsed("CVE-2026-0001", RCE)
    ui.summary_table([row(b, [], [])], [])
    assert "Needs" not in capsys.readouterr().out


def test_ai_payload_gets_preconditions_and_exclusions(monkeypatch):
    sent = {}

    class Client:
        def __init__(self):
            self.models = types.SimpleNamespace(list=lambda limit: [types.SimpleNamespace(id="claude-sonnet-x")])
            self.messages = types.SimpleNamespace(create=self.create)

        def create(self, **kw):
            sent.update(kw)
            return types.SimpleNamespace(content=[types.SimpleNamespace(type="text", text="ok")],
                                         stop_reason="end_turn")
    monkeypatch.setitem(sys.modules, "anthropic", types.SimpleNamespace(Anthropic=Client))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    monkeypatch.setattr(analysis, "_MODEL", None)
    r = parsed("CVE-2023-44487", DOS)
    analysis.explain(r, None, {"level": "high"}, pre=preconditions.tags(r), excluded=["dos"])
    text = sent["messages"][0]["content"]
    payload = json.loads(text.split("```json\n")[1].split("\n```")[0])
    assert payload["preconditions"][0]["tag"] == "dos_only" and payload["program_excludes"] == ["dos"]
    assert "program_excludes" in sent["system"]


def test_api_marks_but_never_drops_excluded_cves(monkeypatch):
    known = {"CVE-2023-44487": parsed("CVE-2023-44487", DOS), "CVE-2026-0001": parsed("CVE-2026-0001", RCE)}
    monkeypatch.setattr(nvd, "collect", lambda cve_id: known.get(cve_id))
    monkeypatch.setattr(epss, "collect_many", lambda ids: {})
    monkeypatch.setattr(kev, "load", lambda: ({}, "cache"))
    monkeypatch.setattr(api.time, "sleep", lambda s: None)
    out = api.lookup_cves(list(known), exclusions=["dos"])
    by_id = {r["cve"]["id"]: r for r in out["results"]}
    assert len(by_id) == 2                                       # nothing hidden
    assert by_id["CVE-2023-44487"]["excluded_by"] == ["dos"]
    assert by_id["CVE-2026-0001"]["excluded_by"] == []
    plain = api.lookup_cves(["CVE-2023-44487"])
    assert plain["results"][0]["verdict"] == by_id["CVE-2023-44487"]["verdict"]   # verdict unchanged


def test_cli_bad_exclusions_file_stops_before_any_lookup(monkeypatch, tmp_path, capsys):
    def boom(*a):
        raise AssertionError("looked something up with a bad exclusions file")
    monkeypatch.setattr(epss, "collect_many", boom)
    monkeypatch.setattr(sys, "argv", ["kaidoku", "CVE-2023-44487", "--exclusions", write(tmp_path, "denial\n")])
    assert cli.main() == 1
    assert "isn't a class" in capsys.readouterr().out


def test_cli_json_carries_preconditions_and_exclusions(monkeypatch, tmp_path, capsys):
    known = {"CVE-2023-44487": parsed("CVE-2023-44487", DOS)}
    monkeypatch.setattr(nvd, "collect", lambda cve_id: known.get(cve_id))
    monkeypatch.setattr(epss, "collect_many", lambda ids: {})
    monkeypatch.setattr(kev, "load", lambda: ({}, "cache"))
    out = tmp_path / "out.json"
    monkeypatch.setattr(sys, "argv", ["kaidoku", "CVE-2023-44487", "--exclusions", write(tmp_path, "dos\n"),
                                      "--json", str(out)])
    assert cli.main() == 0
    [r] = json.loads(out.read_text())
    assert r["preconditions"][0]["tag"] == "dos_only" and r["excluded_by"] == ["dos"]
    assert "Program exclusions: dos" in capsys.readouterr().out
