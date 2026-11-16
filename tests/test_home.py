"""Where Kaidoku keeps reports/ and cache/ (v0.8, kaidoku/home.py)."""

import os

from kaidoku import home


def test_kaidoku_home_wins(monkeypatch, tmp_path):
    monkeypatch.setenv("KAIDOKU_HOME", str(tmp_path))
    folder, why = home.where_data_lives()
    assert folder == str(tmp_path) and why == "KAIDOKU_HOME is set"
    assert home.data_dir("reports") == os.path.join(str(tmp_path), "reports")


def test_running_from_this_clone_uses_the_clone(monkeypatch):
    monkeypatch.delenv("KAIDOKU_HOME", raising=False)
    folder, why = home.where_data_lives()
    assert folder == home.REPO_DIR and "repo folder" in why


def test_installed_package_uses_dot_kaidoku(monkeypatch, tmp_path):
    monkeypatch.delenv("KAIDOKU_HOME", raising=False)
    monkeypatch.setattr(home, "running_from_repo", lambda folder=None: False)
    folder, _ = home.where_data_lives()
    assert folder == os.path.join(os.path.expanduser("~"), ".kaidoku")


def test_only_kaidokus_own_pyproject_counts(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "something-else"\n', encoding="utf-8")
    assert home.running_from_repo(str(tmp_path)) is False
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "kaidoku"\n', encoding="utf-8")
    assert home.running_from_repo(str(tmp_path)) is True
    assert home.running_from_repo(str(tmp_path / "missing")) is False
