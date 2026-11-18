"""v0.9: days between the NVD publishing a CVE and CISA adding it to KEV."""

from kaidoku import ui
from kaidoku.sources import kev


def test_days_after_publication():
    assert kev.days_to_kev("2021-12-07", "2021-12-10") == 3


def test_same_day():
    assert kev.days_to_kev("2024-04-12", "2024-04-12") == 0


def test_listed_before_publication_is_negative():
    assert kev.days_to_kev("2024-04-24", "2024-04-12") == -12


def test_full_nvd_timestamp_is_cut_to_the_date():
    assert kev.days_to_kev("2021-12-10T10:15:09.143", "2021-12-10") == 0


def test_missing_or_broken_dates_are_none():
    assert kev.days_to_kev(None, "2024-04-12") is None
    assert kev.days_to_kev("2024-04-12", None) is None
    assert kev.days_to_kev("", "2024-04-12") is None
    assert kev.days_to_kev("not a date", "2024-04-12") is None


def test_apply_adds_days_from_cisa_feed():
    record = {"id": "CVE-2021-44228", "published": "2021-12-10", "kev": None}
    catalog = {"CVE-2021-44228": {"date_added": "2021-12-10", "ransomware": True}}
    kev.apply(record, catalog)
    assert record["kev"]["days_after_published"] == 0
    assert "days_after_published" not in catalog["CVE-2021-44228"]  # the catalog itself is untouched


def test_apply_adds_days_when_only_nvd_says_kev():
    record = {"id": "CVE-2099-0001", "published": "2099-01-01", "kev": {"date_added": "2099-01-31"}}
    kev.apply(record, {})
    assert record["kev"]["days_after_published"] == 30
    assert record["kev"]["ransomware"] is None


def test_apply_leaves_non_kev_cves_alone():
    record = {"id": "CVE-2099-0002", "published": "2099-01-01", "kev": None}
    kev.apply(record, {})
    assert record["kev"] is None


def test_card_wording():
    assert ui._kev_timing({}) == ""
    assert ui._kev_timing({"days_after_published": None}) == ""
    assert ui._kev_timing({"days_after_published": 0}) == ", the same day it was published"
    assert ui._kev_timing({"days_after_published": 1}) == ", 1 day after publication"
    assert ui._kev_timing({"days_after_published": 3}) == ", 3 days after publication"
    assert "12 days before the NVD published it" in ui._kev_timing({"days_after_published": -12})
    assert "before the NVD record existed" in ui._kev_timing({"days_after_published": -12})
    assert "disclosure" not in ui._kev_timing({"days_after_published": -12})
    assert "1 day before" in ui._kev_timing({"days_after_published": -1})
