"""How the core locates the contract it validates every request against.

Installed as a standalone plugin checkout, the package no longer sits inside
the application repository, so the historical "walk up from this file" lookup
has nothing to find. These tests pin the resolution order the core actually
uses, including the operator override that a standalone deployment depends on.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from open_android_intelligence_gateway.contract_assets import CONTRACT_ROOT_ENV
from open_android_intelligence_gateway.core import GatewayError, _contract_root

PROBE_FILES = (
    "core-dispatched-schemas.json",
    "schemas/envelope.schema.json",
    "vectors/vector-set-1.0.0.schema.json",
)


def _contract_at(root: Path) -> Path:
    for probe in PROBE_FILES:
        target = root / probe
        target.parent.mkdir(parents=True, exist_ok=True)
        # The registry indexes documents by ``$id``, so a fixture without one is
        # not a schema set it would accept.
        document = {"$id": f"https://contracts.example.test/{probe}", "type": "object"}
        target.write_text(json.dumps(document), encoding="utf-8")
    return root


def test_configured_directory_is_used_when_no_contract_is_above(tmp_path, monkeypatch):
    contract = _contract_at(tmp_path / "configured-contract")
    empty_cwd = tmp_path / "empty-cwd"
    empty_cwd.mkdir()
    monkeypatch.setenv(CONTRACT_ROOT_ENV, str(contract))
    # Run where no contract exists above the working directory, so only the
    # operator override can explain a successful resolution.
    monkeypatch.chdir(empty_cwd)

    assert _contract_root() == contract


@pytest.fixture
def isolated_plugin_directory():
    """Hide any contract already materialised in this checkout.

    Without this, a developer who ran the plugin locally has a real contract
    one level above the package, and the upward search legitimately finds it
    before reaching anything the test set up.
    """
    import shutil

    local = Path(__file__).resolve().parents[1] / "gateway-contract"
    backup = local.with_name("gateway-contract._hidden_by_test")
    moved = False
    if local.is_dir():
        shutil.move(str(local), str(backup))
        moved = True
    try:
        yield
    finally:
        if moved and not local.exists():
            shutil.move(str(backup), str(local))


def test_working_directory_is_not_a_contract_source(tmp_path, monkeypatch, isolated_plugin_directory):
    """The working directory must never become a contract source.

    Searching upwards from the CWD let an application checkout satisfy the
    Gateway with a contract that was never checked against this plugin pin:
    ``contract status`` would report "not ready" while the Gateway served one
    anyway. Every remaining source is explicit and checkable - an argument,
    the environment, or this checkout own materialised copy.
    """
    application = tmp_path / "app"
    _contract_at(application / "gateway-contract")
    monkeypatch.delenv(CONTRACT_ROOT_ENV, raising=False)
    monkeypatch.chdir(application)

    with pytest.raises(GatewayError):
        _contract_root()


def test_explicit_argument_outranks_the_operator_override(tmp_path, monkeypatch):
    explicit = _contract_at(tmp_path / "explicit-contract")
    monkeypatch.setenv(CONTRACT_ROOT_ENV, str(_contract_at(tmp_path / "configured")))

    assert _contract_root(str(explicit)) == explicit


def test_explicit_argument_outranks_the_upward_search(tmp_path, monkeypatch):
    upward = _contract_at(tmp_path / "upward" / "gateway-contract")
    explicit = _contract_at(tmp_path / "explicit-contract")
    monkeypatch.delenv(CONTRACT_ROOT_ENV, raising=False)
    monkeypatch.chdir(upward)

    assert _contract_root(str(explicit)) == explicit