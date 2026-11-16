"""
CVSS 3.x and 4.0 together (v0.7.1). The verdict and ranking keep using the
v3.x score (comparable across CVEs); a v4.0 score that exists alongside is
shown and sent to the AI too, and v4.0 vectors are explained.

Run with:  python3 -m pytest -v
"""

import json
import sys
import types

from kaidoku import analysis, triage, ui
from kaidoku.sources import nvd

V31 = {"source": "cna", "type": "Secondary", "cvssData": {
    "version": "3.1", "baseScore": 8.1, "baseSeverity": "HIGH",
    "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"}}
V40 = {"source": "cna", "type": "Secondary", "cvssData": {
    "version": "4.0", "baseScore": 9.2, "baseSeverity": "CRITICAL",
    "vectorString": "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}}
V40_ADJ = {"source": "cna", "type": "Secondary", "cvssData": {
    "version": "4.0", "baseScore": 9.4, "baseSeverity": "CRITICAL",
    "vectorString": "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"}}


def record(**metrics):
    return {"id": "CVE-2026-0001", "vulnStatus": "Deferred", "published": "2026-11-13",
            "metrics": metrics, "descriptions": [{"lang": "en", "value": "test"}]}


def test_both_scores_keep_v31_for_the_verdict_and_add_v4():
    d = nvd.parse(record(cvssMetricV31=[V31], cvssMetricV40=[V40]))
    assert d["cvss"]["version"] == "3.1" and d["cvss"]["score"] == 8.1
    assert d["cvss_v4"]["version"] == "4.0" and d["cvss_v4"]["score"] == 9.2
    assert d["vector_explained"][0] == ("Attack vector", "Network (remote)")


def test_v4_only_is_the_main_score_and_not_shown_twice():
    d = nvd.parse(record(cvssMetricV40=[V40_ADJ]))
    assert d["cvss"]["version"] == "4.0" and d["cvss_v4"] is None


def test_v31_only_has_no_v4():
    assert nvd.parse(record(cvssMetricV31=[V31]))["cvss_v4"] is None


def test_no_scores_at_all():
    d = nvd.parse(record())
    assert d["cvss"] is None and d["cvss_v4"] is None and d["vector_explained"] == []


def test_the_v4_score_never_changes_the_verdict():
    with_v4 = triage.verdict(nvd.parse(record(cvssMetricV31=[V31], cvssMetricV40=[V40])), None)
    without = triage.verdict(nvd.parse(record(cvssMetricV31=[V31])), None)
    assert with_v4 == without


def test_v4_vectors_are_explained():
    parts = dict(nvd.explain_vector(V40_ADJ["cvssData"]["vectorString"]))
    assert parts["Attack vector"] == "Adjacent network"
    assert parts["Attack requirements"] == "None"
    assert parts["Downstream conf. impact"] == "High"
    assert len(parts) == 11                          # the 11 base metrics


def test_v4_threat_and_environment_parts_are_left_out():
    parts = dict(nvd.explain_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A/CR:H"))
    assert len(parts) == 11


def test_unknown_vector_versions_still_explain_nothing():
    assert nvd.explain_vector("CVSS:2.0/AV:N") == [] and nvd.explain_vector("") == []


def test_card_shows_both_scores_and_the_v4_attack_table(capsys, monkeypatch):
    monkeypatch.setattr(ui, "ENABLED", False)
    d = nvd.parse(record(cvssMetricV31=[V31], cvssMetricV40=[V40]))
    ui.cve_card(d, None, triage.verdict(d, None))
    out = capsys.readouterr().out
    assert "CVSS 3.1      8.1  HIGH" in out and "CVSS 4.0      9.2  CRITICAL" in out
    assert out.index("CVSS 3.1") < out.index("CVSS 4.0")        # the verdict's score first
    v4 = nvd.parse(record(cvssMetricV40=[V40_ADJ]))
    ui.cve_card(v4, None, triage.verdict(v4, None))
    out = capsys.readouterr().out
    assert out.count("CVSS 4.0") == 1 and "Adjacent network" in out and "Attack requirements" in out


def test_json_output_keeps_cvss_and_adds_cvss_v4():
    d = nvd.parse(record(cvssMetricV31=[V31], cvssMetricV40=[V40]))
    saved = json.loads(json.dumps(d))
    assert saved["cvss"]["score"] == 8.1 and saved["cvss_v4"]["score"] == 9.2


class FakeClient:
    sent = []

    def __init__(self):
        self.models = types.SimpleNamespace(
            list=lambda limit: [types.SimpleNamespace(id="claude-sonnet-test")])
        self.messages = types.SimpleNamespace(create=self.create)

    def create(self, *, model, max_tokens, system, messages):
        FakeClient.sent.append({"system": system, "content": messages[0]["content"]})
        block = types.SimpleNamespace(type="text", text="## 1. What it is\\nTest.")
        return types.SimpleNamespace(content=[block], stop_reason="end_turn")


def test_ai_gets_both_scores_and_which_one_the_verdict_uses(monkeypatch):
    FakeClient.sent = []
    monkeypatch.setitem(sys.modules, "anthropic", types.SimpleNamespace(Anthropic=FakeClient))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(analysis, "_MODEL", None)
    d = nvd.parse(record(cvssMetricV31=[V31], cvssMetricV40=[V40]))
    analysis.explain(d, None, triage.verdict(d, None))
    content = FakeClient.sent[0]["content"]
    payload = json.loads(content[content.index("{"):content.rindex("}") + 1])
    assert payload["cvss_used_for_verdict"] == "CVSS 3.1"
    assert payload["nvd"]["cvss_v4"]["score"] == 9.2
    assert payload["cvss_v4_plain_english"]["Attack requirements"].startswith("Present")
    assert "give both in section 4" in FakeClient.sent[0]["system"]
