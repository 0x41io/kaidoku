"""Tests for monomi_import.py: which CVEs in a monomi scan are the target's."""

import json

import pytest

from kaidoku import monomi_import


def scan(tmp_path, ips):
    path = tmp_path / "scan.json"
    path.write_text(json.dumps({"target": "shop.test", "exposure": {"ips": ips}}))
    return str(path)


def test_cves_keep_where_they_were_found(tmp_path):
    path = scan(tmp_path, {"9.9.9.9": {"shared_edge": False, "hosts": ["app.shop.test"],
                                       "vulns": ["cve-2024-0001"]}})
    target, ids, found_on = monomi_import.load(path)
    assert target == "shop.test" and ids == ["CVE-2024-0001"]
    assert found_on["CVE-2024-0001"] == [{"ip": "9.9.9.9", "hosts": ["app.shop.test"]}]


def test_cdn_edges_and_someone_elses_servers_are_skipped(tmp_path):
    # v0.10.2, from the Superdrug run: CVEs on Google's shared front end
    path = scan(tmp_path, {
        "104.21.9.101": {"shared_edge": True, "hosts": ["www"], "vulns": ["CVE-2023-44487"]},
        "216.239.32.21": {"shared_edge": False, "not_own": "third-party hosting (Google front end)",
                          "hosts": ["ecom"], "vulns": ["CVE-2021-41184"]},
        "9.9.9.9": {"shared_edge": False, "hosts": ["app"], "vulns": ["CVE-2024-0001"]}})
    _, ids, found_on = monomi_import.load(path)
    assert ids == ["CVE-2024-0001"] and list(found_on) == ["CVE-2024-0001"]


def test_a_scan_from_before_the_label_skips_only_edges(tmp_path):
    # Older monomi scans have no "not_own": nothing else is guessed
    path = scan(tmp_path, {"216.239.32.21": {"shared_edge": False, "hosts": ["ecom"],
                                             "vulns": ["CVE-2021-41184"]}})
    assert monomi_import.load(path)[1] == ["CVE-2021-41184"]


def test_a_scan_without_port_data_says_so(tmp_path):
    path = tmp_path / "scan.json"
    path.write_text(json.dumps({"target": "shop.test"}))
    with pytest.raises(ValueError, match="no port/CVE data"):
        monomi_import.load(str(path))
