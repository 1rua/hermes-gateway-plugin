"""How the plugin hands the resolved contract to the core it builds.

The core discovers the contract by walking up from its own file, which works
while the plugin sits inside the application repository and stops working the
moment it is installed as a standalone checkout. These tests pin the seam where
the plugin resolves the contract and passes it in explicitly.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from open_android_intelligence_gateway import plugin as plugin_module
from open_android_intelligence_gateway.contract_assets import CONTRACT_ROOT_ENV
from test_support import make_secret_store

PROBE_FILES = (
    "core-dispatched-schemas.json",
    "schemas/envelope.schema.json",
    "vectors/vector-set-1.0.0.schema.json",
)


class MinimalHostContext:
    """Only the attributes ``compose_gateway_services`` reads.

    Registration itself is covered by ``test_host_registration``; this double
    exists so a contract-injection test does not have to stand up a whole host.
    """

    def __init__(self, plugin_data_dir, **overrides):
        self.plugin_data_dir = plugin_data_dir
        self.secret_store = make_secret_store()
        self.__dict__.update(overrides)


def _ready_contract(plugin_root: Path) -> Path:
    contract = plugin_root / "gateway-contract"
    for probe in PROBE_FILES:
        target = contract / probe
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text('{"type": "object"}\n', encoding="utf-8")
    return contract


def test_compose_gateway_services_injects_the_resolved_contract_root(tmp_path, monkeypatch):
    plugin_root = tmp_path / "plugin"
    plugin_root.mkdir()
    contract = _ready_contract(plugin_root)
    monkeypatch.setattr(plugin_module, "plugin_root", lambda: plugin_root)
    monkeypatch.setenv(CONTRACT_ROOT_ENV, str(contract))

    services = plugin_module.compose_gateway_services(MinimalHostContext(tmp_path / "data"))

    assert services.core.contract_root == contract.resolve()


def test_host_supplied_contract_root_wins_over_the_plugin_default(tmp_path, monkeypatch):
    plugin_root = tmp_path / "plugin"
    plugin_root.mkdir()
    _ready_contract(plugin_root)
    host_contract = _ready_contract(tmp_path / "host-contract")
    monkeypatch.setattr(plugin_module, "plugin_root", lambda: plugin_root)
    monkeypatch.setenv(CONTRACT_ROOT_ENV, str(plugin_root / "gateway-contract"))

    services = plugin_module.compose_gateway_services(
        MinimalHostContext(tmp_path / "data", contract_root=host_contract)
    )

    assert services.core.contract_root == host_contract.resolve()


class CliHostContext(MinimalHostContext):
    """A host that accepts the native subcommand the plugin registers."""

    def __init__(self, plugin_data_dir, **overrides):
        super().__init__(plugin_data_dir, **overrides)
        self.commands: dict = {}

    def register_platform(self, platform):
        self.platform_id = platform.platform_id

    def register_admin(self, admin):
        self.admin = admin

    def register_http_route(self, route):
        pass

    def register_cli_command(self, name, help, setup_fn, handler_fn):
        self.commands[name] = (setup_fn, handler_fn)


def _run_contract_cli(ctx, capsys, *argv) -> str:
    setup_fn, handler_fn = ctx.commands["open-android-intelligence"]
    parser = argparse.ArgumentParser()
    setup_fn(parser)
    handler_fn(parser.parse_args(list(argv)))
    return capsys.readouterr().out


def test_contract_status_reports_the_pinned_revision_when_ready(tmp_path, monkeypatch, capsys):
    plugin_root = tmp_path / "plugin"
    plugin_root.mkdir()
    _ready_contract(plugin_root)
    monkeypatch.setattr(plugin_module, "plugin_root", lambda: plugin_root)
    monkeypatch.setenv(CONTRACT_ROOT_ENV, str(plugin_root / "gateway-contract"))
    ctx = CliHostContext(tmp_path / "data")

    plugin_module.register(ctx)
    report = _run_contract_cli(ctx, capsys, "contract", "status")

    assert str(plugin_root / "gateway-contract") in report
    assert "env" in report


def test_contract_status_states_why_the_contract_is_not_ready(tmp_path, monkeypatch, capsys):
    plugin_root = tmp_path / "plugin"
    plugin_root.mkdir()
    monkeypatch.delenv(CONTRACT_ROOT_ENV, raising=False)
    monkeypatch.setattr(plugin_module, "plugin_root", lambda: plugin_root)
    ctx = CliHostContext(tmp_path / "data")

    plugin_module.register(ctx)
    report = _run_contract_cli(ctx, capsys, "contract", "status")

    assert "未就绪" in report
    assert str(plugin_root / "contract-pin.json") in report


def _local_contract_source(root: Path) -> str:
    """A real local git repository holding the contract; returns its commit."""
    source = root / "contract-source"
    for probe in PROBE_FILES:
        target = source / "gateway-contract" / probe
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text('{"type": "object"}\n', encoding="utf-8")

    def git(*args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=source, check=True, capture_output=True, text=True,
        ).stdout.strip()

    git("init", "-b", "main")
    git("config", "user.email", "plugin-tests@example.com")
    git("config", "user.name", "Plugin Tests")
    git("add", ".")
    git("commit", "-m", "publish contract")
    return git("rev-parse", "HEAD")


def test_contract_sync_repairs_a_damaged_contract_tree(tmp_path, monkeypatch, capsys):
    plugin_root = tmp_path / "plugin"
    plugin_root.mkdir()
    revision = _local_contract_source(tmp_path)
    (plugin_root / "contract-pin.json").write_text(
        json.dumps({"repository": str(tmp_path / "contract-source"), "revision": revision}),
        encoding="utf-8",
    )
    monkeypatch.delenv(CONTRACT_ROOT_ENV, raising=False)
    monkeypatch.setattr(plugin_module, "plugin_root", lambda: plugin_root)
    ctx = CliHostContext(tmp_path / "data")
    plugin_module.register(ctx)
    # Loading never reaches the network, so the first acquisition is explicit.
    _run_contract_cli(ctx, capsys, "contract", "sync")
    (plugin_root / "gateway-contract" / PROBE_FILES[0]).unlink()

    report = _run_contract_cli(ctx, capsys, "contract", "sync")

    assert (plugin_root / "gateway-contract" / PROBE_FILES[0]).is_file()
    assert revision in report
    assert "未就绪" not in report