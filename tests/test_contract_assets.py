"""Contract asset acquisition for the standalone Hermes plugin repository.

The plugin ships no copy of the Gateway Protocol contract. These tests pin
the acquisition seam — ``resolve_contract_root`` — and drive it against real
local git repositories, so the clone, the revision pin and the idempotency are
observed as an operator would observe them rather than through a stubbed git.
"""

import json
import subprocess
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from open_android_intelligence_gateway.contract_assets import (
    CONTRACT_ROOT_ENV,
    resolve_contract_root,
)


@pytest.fixture(autouse=True)
def _without_operator_override(monkeypatch):
    """These tests exercise the pinned fetch, not the operator override.

    ``conftest`` points the suite at a real contract so the negotiated digest
    is genuine; that override would otherwise short-circuit every pin path
    here, so each test starts from an environment that has none.
    """
    monkeypatch.delenv(CONTRACT_ROOT_ENV, raising=False)

PROBE_FILES = (
    "schemas/envelope.schema.json",
    "vectors/vector-set-1.0.0.schema.json",
)

PIN_FILE_NAME = "contract-pin.json"


def _git(repository: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repository, check=True, capture_output=True, text=True,
    )
    return result.stdout.strip()


def _contract_source(tmp_path: Path) -> tuple[Path, str]:
    """A real git repository whose ``gateway-contract`` tree is complete."""
    source = tmp_path / "contract-source"
    for probe in PROBE_FILES:
        target = source / "gateway-contract" / probe
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text('{"type": "object"}\n', encoding="utf-8")
    _git(source, "init", "-b", "main")
    _git(source, "config", "user.email", "plugin-tests@example.com")
    _git(source, "config", "user.name", "Plugin Tests")
    _git(source, "add", ".")
    _git(source, "commit", "-m", "publish contract")
    return source, _git(source, "rev-parse", "HEAD")


def test_only_the_contract_subtree_is_materialised(tmp_path):
    """The pinned repository is a whole application; only the contract is wanted.

    Checking out everything would pull the entire Android tree into the plugin
    directory on every fresh install, so the acquisition is narrowed to the
    one directory the Gateway actually reads.
    """
    source, revision = _contract_source(tmp_path)
    build_file = source / "apps" / "android" / "build.gradle.kts"
    build_file.parent.mkdir(parents=True, exist_ok=True)
    build_file.write_text("// unrelated application source\n", encoding="utf-8")
    _git(source, "add", ".")
    _git(source, "commit", "-m", "add application sources")
    revision = _git(source, "rev-parse", "HEAD")
    plugin_root = tmp_path / "plugin"
    _write_pin(plugin_root, source, revision)

    resolution = resolve_contract_root(plugin_root)

    assert resolution.root == plugin_root / "gateway-contract"
    assert not (plugin_root / "apps").exists()
    for probe in PROBE_FILES:
        assert (resolution.root / probe).is_file()


def _write_pin(plugin_root: Path, repository: Path, revision: str) -> Path:
    plugin_root.mkdir(parents=True, exist_ok=True)
    pin = plugin_root / PIN_FILE_NAME
    pin.write_text(
        json.dumps(
            {
                "repository": str(repository),
                "revision": revision,
                "probes": list(PROBE_FILES),
            }
        ),
        encoding="utf-8",
    )
    return pin


def test_clones_the_pinned_contract_revision_into_the_plugin_directory(tmp_path):
    source, revision = _contract_source(tmp_path)
    plugin_root = tmp_path / "plugin"
    _write_pin(plugin_root, source, revision)

    resolution = resolve_contract_root(plugin_root)

    assert resolution.source == "pin"
    assert resolution.pinned_ref == revision
    assert resolution.root == plugin_root / "gateway-contract"
    for probe in PROBE_FILES:
        assert (resolution.root / probe).is_file()


def test_reuses_an_already_materialised_contract(tmp_path):
    source, revision = _contract_source(tmp_path)
    plugin_root = tmp_path / "plugin"
    _write_pin(plugin_root, source, revision)
    resolve_contract_root(plugin_root)

    resolution = resolve_contract_root(plugin_root)

    assert resolution.source == "cached"
    assert resolution.pinned_ref == revision
    assert resolution.root == plugin_root / "gateway-contract"


def test_reports_an_unreachable_source_instead_of_raising(tmp_path):
    missing = tmp_path / "missing-repository"
    plugin_root = tmp_path / "plugin"
    _write_pin(plugin_root, missing, "0" * 40)

    resolution = resolve_contract_root(plugin_root)

    assert resolution.source == "unavailable"
    assert resolution.root is None
    assert resolution.pinned_ref == "0" * 40
    assert str(missing) in resolution.reason
    assert not (plugin_root / "gateway-contract").exists()


def test_uses_an_operator_supplied_contract_root_without_fetching(tmp_path, monkeypatch):
    supplied = tmp_path / "offline-contract"
    for probe in PROBE_FILES:
        target = supplied / probe
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text('{"type": "object"}\n', encoding="utf-8")
    plugin_root = tmp_path / "plugin"
    # The pin cannot be fetched, so an "env" result proves git was never run.
    _write_pin(plugin_root, tmp_path / "missing-repository", "0" * 40)
    monkeypatch.setenv(CONTRACT_ROOT_ENV, str(supplied))

    resolution = resolve_contract_root(plugin_root)

    assert resolution.source == "env"
    assert resolution.root == supplied


def test_force_realigns_a_damaged_contract_tree(tmp_path):
    source, revision = _contract_source(tmp_path)
    plugin_root = tmp_path / "plugin"
    _write_pin(plugin_root, source, revision)
    resolve_contract_root(plugin_root)
    (plugin_root / "gateway-contract" / PROBE_FILES[0]).unlink()

    resolution = resolve_contract_root(plugin_root, force=True)

    assert resolution.source == "pin"
    assert resolution.pinned_ref == revision
    assert (resolution.root / PROBE_FILES[0]).is_file()


def test_concurrent_loads_do_not_corrupt_the_contract_tree(tmp_path):
    source, revision = _contract_source(tmp_path)
    plugin_root = tmp_path / "plugin"
    _write_pin(plugin_root, source, revision)

    workers = 4
    barrier = threading.Barrier(workers)
    resolutions: list = []
    failures: list = []

    def worker() -> None:
        barrier.wait()
        try:
            resolutions.append(resolve_contract_root(plugin_root))
        except Exception as exc:  # noqa: BLE001 - the behaviour under test
            failures.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert failures == []
    assert len(resolutions) == workers
    for probe in PROBE_FILES:
        assert (plugin_root / "gateway-contract" / probe).is_file()
    # Whoever did the work, every caller must land on the same pinned tree
    # rather than a half-written one.
    for resolution in resolutions:
        assert resolution.root == plugin_root / "gateway-contract"
        assert resolution.pinned_ref == revision


def test_reports_a_missing_pin_instead_of_raising(tmp_path):
    plugin_root = tmp_path / "plugin"
    plugin_root.mkdir()

    resolution = resolve_contract_root(plugin_root)

    assert resolution.source == "unavailable"
    assert resolution.root is None
    assert PIN_FILE_NAME in resolution.reason


def test_refuses_a_pin_that_does_not_name_a_full_commit_sha(tmp_path):
    plugin_root = tmp_path / "plugin"
    _write_pin(plugin_root, tmp_path / "contract-source", "abc123")

    resolution = resolve_contract_root(plugin_root)

    assert resolution.source == "unavailable"
    assert resolution.root is None
    # Rejected on the pin itself, not incidentally by a failing fetch: a short
    # SHA would otherwise make the pin look authoritative while addressing a
    # revision the operator never chose.
    assert "40 位" in resolution.reason
    assert "abc123" in resolution.reason