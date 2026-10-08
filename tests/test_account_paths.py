"""Default storage root resolution: explicit configuration, never the shell."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from open_android_intelligence_gateway.account_paths import (
    DEFAULT_ROOT_ENVIRONMENT_VARIABLE,
    default_hermes_gateway_root,
)


def test_configured_root_wins(monkeypatch, tmp_path):
    monkeypatch.setenv(DEFAULT_ROOT_ENVIRONMENT_VARIABLE, str(tmp_path))

    assert default_hermes_gateway_root() == (tmp_path / "accounts").resolve()


def test_default_root_does_not_follow_the_working_directory(monkeypatch, tmp_path):
    monkeypatch.delenv(DEFAULT_ROOT_ENVIRONMENT_VARIABLE, raising=False)
    monkeypatch.chdir(tmp_path)

    root = default_hermes_gateway_root()

    assert root.is_absolute()
    assert tmp_path.resolve() not in root.parents
    assert Path.cwd().resolve() not in root.parents


def test_default_root_is_stable_across_working_directories(monkeypatch, tmp_path):
    monkeypatch.delenv(DEFAULT_ROOT_ENVIRONMENT_VARIABLE, raising=False)
    monkeypatch.chdir(tmp_path)
    first = default_hermes_gateway_root()

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    assert default_hermes_gateway_root() == first
