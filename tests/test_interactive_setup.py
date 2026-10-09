import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import pytest
from open_android_intelligence_gateway.admin import create_admin_service, HostApiCompatibility
from open_android_intelligence_gateway.core import create_gateway_core
from open_android_intelligence_gateway.plugin import interactive_setup


def _compatible_host_api():
    return HostApiCompatibility("1.0.0", "3.0.0", "0" * 40)


def test_interactive_setup_success(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    admin = create_admin_service(core=core, host_version="2.0.0", host_api=_compatible_host_api())

    inputs = iter([
        "y",            # Create account?
        "phone1",       # Username
        "y",            # Local confirmation?
    ])
    passwords = iter([
        "supersecret1",  # Password
        "supersecret1",  # Password confirm
    ])

    success = interactive_setup(
        admin=admin,
        input_fn=lambda prompt="": next(inputs),
        getpass_fn=lambda prompt="": next(passwords),
        is_tty=True,
    )

    assert success is True
    assert core.has_gateway_account("phone1")
    account = core.open_gateway_account("phone1")
    try:
        assert account.credentials.verify_password("supersecret1") is True
        assert account.credentials.verify_password("wrong") is False
    finally:
        account.close()


def test_interactive_setup_decline_creates_no_account(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    admin = create_admin_service(core=core, host_version="2.0.0", host_api=_compatible_host_api())

    inputs = iter(["n"])  # Decline account

    success = interactive_setup(
        admin=admin,
        input_fn=lambda prompt="": next(inputs),
        getpass_fn=lambda prompt="": "",
        is_tty=True,
    )

    assert success is True
    assert not (tmp_path / "accounts").exists() or len(list((tmp_path / "accounts").iterdir())) == 0


def test_interactive_setup_non_tty_falls_back_safely(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    admin = create_admin_service(core=core, host_version="2.0.0", host_api=_compatible_host_api())

    # Should not call input_fn or getpass_fn at all
    def fail_if_called(prompt=""):
        pytest.fail("input_fn should not be called in non-tty mode")

    success = interactive_setup(
        admin=admin,
        input_fn=fail_if_called,
        getpass_fn=fail_if_called,
        is_tty=False,
    )

    assert success is True
    assert not core.has_gateway_account("phone1")


def test_interactive_setup_read_only_blocks(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    admin = create_admin_service(core=core, host_version="not-compatible", host_api=_compatible_host_api())
    assert admin.read_only is True

    success = interactive_setup(
        admin=admin,
        is_tty=True,
    )

    assert success is False


def test_interactive_setup_retries_invalid_username_and_password_mismatch(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    admin = create_admin_service(core=core, host_version="2.0.0", host_api=_compatible_host_api())

    inputs = iter([
        "y",               # Create account?
        "",                # Empty username (retry)
        "bad name with spaces!", # Invalid format (retry)
        "good_phone_2",    # Valid username
        "y",               # Local confirmation?
    ])
    passwords = iter([
        "",                # Empty password (retry)
        "passA",           # Password attempt 1
        "passB",           # Mismatched confirm (retry)
        "passCorrect123",  # Password attempt 2
        "passCorrect123",  # Matched confirm
    ])

    success = interactive_setup(
        admin=admin,
        input_fn=lambda prompt="": next(inputs),
        getpass_fn=lambda prompt="": next(passwords),
        is_tty=True,
    )

    assert success is True
    assert core.has_gateway_account("good_phone_2")
    account = core.open_gateway_account("good_phone_2")
    try:
        assert account.credentials.verify_password("passCorrect123") is True
    finally:
        account.close()


def test_interactive_setup_cancel_at_confirmation(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    admin = create_admin_service(core=core, host_version="2.0.0", host_api=_compatible_host_api())

    inputs = iter([
        "y",          # Create account?
        "cancel_me",  # Valid username
        "n",          # Deny local confirmation
    ])
    passwords = iter([
        "secretpass1",
        "secretpass1",
    ])

    success = interactive_setup(
        admin=admin,
        input_fn=lambda prompt="": next(inputs),
        getpass_fn=lambda prompt="": next(passwords),
        is_tty=True,
    )

    assert success is False
    assert not core.has_gateway_account("cancel_me")


def test_interactive_setup_shows_port_from_env(tmp_path, monkeypatch, capsys):
    import os
    monkeypatch.setenv("OPEN_ANDROID_GATEWAY_PORT", "9090")
    core = create_gateway_core(storage_root=tmp_path)
    admin = create_admin_service(core=core, host_version="2.0.0", host_api=_compatible_host_api())

    inputs = iter([
        "y",
        "port_user",
        "y",
    ])
    passwords = iter([
        "secret12345",
        "secret12345",
    ])

    success = interactive_setup(
        admin=admin,
        input_fn=lambda prompt="": next(inputs),
        getpass_fn=lambda prompt="": next(passwords),
        is_tty=True,
    )

    assert success is True
    captured = capsys.readouterr()
    assert "9090" in captured.out


def test_interactive_setup_auto_syncs_contract_when_missing(tmp_path, monkeypatch, capsys):
    import json
    import shutil
    import subprocess
    from open_android_intelligence_gateway import plugin as plugin_module

    # Create a local git repository holding genuine contract files
    real_contract = Path(__file__).resolve().parents[1] / "gateway-contract"
    source = tmp_path / "contract-source"
    shutil.copytree(real_contract, source / "gateway-contract")

    def _git(*args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=source, check=True, capture_output=True, text=True,
        ).stdout.strip()

    _git("init", "-b", "main")
    _git("config", "user.email", "test@example.test")
    _git("config", "user.name", "Test Operator")
    _git("add", ".")
    _git("commit", "-m", "init contract")
    revision = _git("rev-parse", "HEAD")

    # Set up mock plugin root with no gateway-contract directory
    plugin_root = tmp_path / "plugin"
    plugin_root.mkdir()
    (plugin_root / "contract-pin.json").write_text(
        json.dumps({"repository": str(source), "revision": revision}),
        encoding="utf-8",
    )
    monkeypatch.delenv("OPEN_ANDROID_GATEWAY_CONTRACT_ROOT", raising=False)
    monkeypatch.setattr(plugin_module, "plugin_root", lambda: plugin_root)

    core = create_gateway_core(storage_root=tmp_path / "data")
    admin = create_admin_service(core=core, host_version="2.0.0", host_api=_compatible_host_api())

    inputs = iter(["y", "auto_phone", "y"])
    passwords = iter(["secret123", "secret123"])

    success = interactive_setup(
        admin=admin,
        input_fn=lambda prompt="": next(inputs),
        getpass_fn=lambda prompt="": next(passwords),
        is_tty=True,
    )

    assert success is True
    assert (plugin_root / "gateway-contract").is_dir()
    assert core.has_gateway_account("auto_phone")
    captured = capsys.readouterr().out
    assert "正在自动同步对应版本的契约代码" in captured
    assert "协议契约同步成功" in captured


def test_interactive_setup_fails_gracefully_when_contract_sync_fails(tmp_path, monkeypatch, capsys):
    import json
    from open_android_intelligence_gateway import plugin as plugin_module

    plugin_root = tmp_path / "plugin-broken"
    plugin_root.mkdir()
    (plugin_root / "contract-pin.json").write_text(
        json.dumps({"repository": str(tmp_path / "does-not-exist"), "revision": "0" * 40}),
        encoding="utf-8",
    )
    monkeypatch.delenv("OPEN_ANDROID_GATEWAY_CONTRACT_ROOT", raising=False)
    monkeypatch.setattr(plugin_module, "plugin_root", lambda: plugin_root)

    core = create_gateway_core(storage_root=tmp_path / "data")
    admin = create_admin_service(core=core, host_version="2.0.0", host_api=_compatible_host_api())

    success = interactive_setup(
        admin=admin,
        input_fn=lambda prompt="": pytest.fail("should not reach input when contract sync fails"),
        getpass_fn=lambda prompt="": "",
        is_tty=True,
    )

    assert success is False
    assert not core.has_gateway_account("phone1")
    captured = capsys.readouterr().out
    assert "协议契约自动拉取失败" in captured


