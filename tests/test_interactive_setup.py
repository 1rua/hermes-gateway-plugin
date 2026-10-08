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


