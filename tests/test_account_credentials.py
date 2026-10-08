"""Account password credentials and the fail-closed login path."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from open_android_intelligence_gateway.adapter import AccountPasswordVerifier
from open_android_intelligence_gateway.admin import HostApiCompatibility, create_admin_service
from open_android_intelligence_gateway.core import GatewayError, create_gateway_core
from open_android_intelligence_gateway.credentials import hash_password, verify_password


HOST_API = HostApiCompatibility("1.0.0", "1.0.0", "0123456789abcdef0123456789abcdef01234567")
INSTALLATION = {
    "installationId": "install_credentials",
    "displayName": "Credentials phone",
    "devicePublicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
}


def _service(core):
    return create_admin_service(core=core, host_version="1.0.0", host_api=HOST_API)


def _create(service, account_id="acct_alice", password="correct horse"):
    return service.execute({"command": "account.create", "input": {
        "accountId": account_id, "password": password, "localConfirmation": True,
    }})


def test_password_digest_round_trip_and_failures():
    digest = hash_password("correct horse battery staple")

    assert digest.startswith("scrypt$")
    assert verify_password("correct horse battery staple", digest) is True
    assert verify_password("wrong", digest) is False
    assert verify_password("correct horse battery staple", "") is False
    assert verify_password("correct horse battery staple", "bcrypt$1$2$3$4$5") is False
    assert verify_password("correct horse battery staple", "scrypt$0$0$0$AAAA$AAAA") is False
    with pytest.raises(ValueError):
        hash_password("")


def test_duplicate_create_does_not_replace_password_or_refresh(tmp_path):
    from test_support import make_secret_store
    core = create_gateway_core(storage_root=tmp_path, secret_store=make_secret_store())
    core.credential_verifier = AccountPasswordVerifier(core)
    service = _service(core)
    assert _create(service)["ok"] is True
    account = core.open_gateway_account("acct_alice")
    try:
        session = account.sessions.create_password_session("acct_alice", "correct horse", INSTALLATION, "cor_duplicate")
        before = tuple(account.store.database.execute("SELECT * FROM account_credentials").fetchone())
        result = _create(service, password="replacement")
        assert result["error"]["code"] == "ACCOUNT_EXISTS"
        assert tuple(account.store.database.execute("SELECT * FROM account_credentials").fetchone()) == before
        assert account.credentials.verify_password("correct horse")
        assert not account.credentials.verify_password("replacement")
        assert account.sessions.refresh(session["refreshCredential"], INSTALLATION["installationId"], session["deviceId"], "cor_still_valid")["accessToken"]
    finally:
        account.close()


def test_password_reset_revokes_all_refresh_families_and_preserves_keys(tmp_path):
    from test_support import make_secret_store
    core = create_gateway_core(storage_root=tmp_path, secret_store=make_secret_store())
    core.credential_verifier = AccountPasswordVerifier(core)
    service = _service(core)
    assert _create(service)["ok"] is True
    account = core.open_gateway_account("acct_alice")
    try:
        installations = [dict(INSTALLATION, installationId="install_one"), dict(INSTALLATION, installationId="install_two")]
        sessions = [account.sessions.create_password_session("acct_alice", "correct horse", item, "cor_reset") for item in installations]
        keys = [tuple(row) for row in account.store.database.execute("SELECT * FROM device_keys ORDER BY device_id")]
        result = service.execute({"command": "account.reset-password", "input": {
            "accountId": "acct_alice", "password": "new password", "localConfirmation": True,
        }})
        assert result["ok"] is True
        assert [tuple(row) for row in account.store.database.execute("SELECT * FROM device_keys ORDER BY device_id")] == keys
        assert not account.credentials.verify_password("correct horse")
        for session, installation in zip(sessions, installations):
            with pytest.raises(GatewayError):
                account.sessions.refresh(session["refreshCredential"], installation["installationId"], session["deviceId"], "cor_reset_refused")
        assert account.sessions.create_password_session("acct_alice", "new password", installations[0], "cor_new_password")["accessToken"]
    finally:
        account.close()


def test_password_reset_rollback_keeps_password_and_refresh(tmp_path):
    from test_support import make_secret_store
    core = create_gateway_core(storage_root=tmp_path, secret_store=make_secret_store())
    core.credential_verifier = AccountPasswordVerifier(core)
    service = _service(core)
    assert _create(service)["ok"] is True
    account = core.open_gateway_account("acct_alice")
    try:
        session = account.sessions.create_password_session("acct_alice", "correct horse", INSTALLATION, "cor_reset")
        account.store.database.execute("CREATE TRIGGER fail_reset BEFORE UPDATE ON refresh_credentials BEGIN SELECT RAISE(ABORT, 'injected reset failure'); END;")
        account.store.database.commit()
        result = service.reset_password({"accountId": "acct_alice", "password": "new password", "localConfirmation": True})
        assert result["ok"] is False
        assert account.credentials.verify_password("correct horse")
        assert account.sessions.active_refresh_credential_count(session["deviceId"]) == 1
    finally:
        account.close()


def test_account_write_requires_a_password_and_local_confirmation(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    service = _service(core)

    missing_password = service.execute({"command": "account.create", "input": {
        "accountId": "acct_alice", "localConfirmation": True,
    }})
    assert missing_password["ok"] is False
    assert missing_password["error"]["code"] == "PASSWORD_REQUIRED"

    unconfirmed = service.execute({"command": "account.create", "input": {
        "accountId": "acct_alice", "password": "pw", "localConfirmation": False,
    }})
    assert unconfirmed["error"]["code"] == "LOCAL_CONFIRMATION_REQUIRED"
    assert core.account_exists("acct_alice") is False

    created = _create(service)
    assert created["ok"] is True
    assert core.account_exists("acct_alice") is True


def test_login_uses_the_recorded_digest_and_nothing_else(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    core.credential_verifier = AccountPasswordVerifier(core)
    _create(_service(core), password="s3cret")

    verifier = core.credential_verifier
    assert verifier.verify("acct_alice", "acct_alice", "s3cret", INSTALLATION) is True
    assert verifier.verify("acct_alice", "acct_alice", "s3cret ", INSTALLATION) is False
    assert verifier.verify("acct_alice", "acct_alice", "", INSTALLATION) is False
    # A username that does not address the account is never a credential match.
    assert verifier.verify("acct_alice", "alice", "s3cret", INSTALLATION) is False
    # An unknown account fails closed instead of being brought into existence.
    assert verifier.verify("acct_unknown", "acct_unknown", "s3cret", INSTALLATION) is False

    account = core.open_gateway_account("acct_alice")
    try:
        assert account.credentials.has_password() is True
        session = account.sessions.create_password_session(
            username="acct_alice", password="s3cret", installation=INSTALLATION,
            correlation_id="cor_login",
        )
        assert session["accessToken"]
        with pytest.raises(GatewayError) as failure:
            account.sessions.create_password_session(
                username="acct_alice", password="wrong", installation=INSTALLATION,
                correlation_id="cor_login_wrong",
            )
        assert failure.value.code == "AUTHENTICATION_FAILED"
    finally:
        account.close()


def test_account_without_a_recorded_password_cannot_be_logged_into(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    core.credential_verifier = AccountPasswordVerifier(core)
    account = core.open_gateway_account("acct_alice")
    account.close()

    assert core.credential_verifier.verify(
        "acct_alice", "acct_alice", "anything", INSTALLATION
    ) is False


def test_account_deletion_is_resource_level_and_requires_confirmation(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    service = _service(core)
    _create(service)
    assert core.account_exists("acct_alice") is True

    unconfirmed = service.execute({
        "command": "account.delete", "accountId": "acct_alice", "localConfirmation": False,
    })
    assert unconfirmed["error"]["code"] == "LOCAL_CONFIRMATION_REQUIRED"
    assert core.account_exists("acct_alice") is True

    missing = service.execute({
        "command": "account.delete", "accountId": "acct_missing", "localConfirmation": True,
    })
    assert missing["error"]["code"] == "ACCOUNT_NOT_FOUND"

    deleted = service.execute({
        "command": "account.delete", "accountId": "acct_alice", "localConfirmation": True,
    })
    assert deleted["ok"] is True
    assert core.account_exists("acct_alice") is False
