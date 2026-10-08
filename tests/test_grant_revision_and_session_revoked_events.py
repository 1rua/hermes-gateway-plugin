"""Pairing grant revisions move on the Gateway, and session revocation reaches
the event stream.

Contract section 11 (`docs/contracts/gateway-protocol-v2.md:780-784`) makes a
pairing's authorization a monotonically increasing `grantRevision`; the Gateway
records the bump in the same transaction as a `pairing.grant.changed` event, and
a request that still carries the old revision answers `GRANT_STALE`. Section 9
(`:671`) lists `session.revoked` among the V2 event types, so a revoked session
is a fact the event stream carries — not only an audit line. Both payloads are
pinned field-by-field against the normative copies in `event.schema.json`
(`$defs.pairingGrantChangedPayload`, `$defs.sessionRevokedPayload`).
"""
from __future__ import annotations
from test_support import enqueue_fixture

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from open_android_intelligence_gateway.admin import (  # noqa: E402
    HostApiCompatibility,
    create_admin_service,
    run_admin_command,
)
from open_android_intelligence_gateway.core import (  # noqa: E402
    ContractRegistry,
    GatewayError,
    TransactionOutcomeUnknown,
    create_gateway_core,
)
from test_support import (  # noqa: E402
    PasswordVerifierDouble,
    make_secret_store,
)

_real_create_gateway_core = create_gateway_core


def create_gateway_core(storage_root=None, **options):
    options.setdefault("secret_store", make_secret_store())
    options.setdefault("credential_verifier", PasswordVerifierDouble())
    return _real_create_gateway_core(storage_root=storage_root, **options)


TEST_HOST_API = HostApiCompatibility(
    "1.0.0", "1.0.0", "0123456789abcdef0123456789abcdef01234567"
)
ACCOUNT_ID = "alice"
INSTALLATION_ID = "install_grant_events"
DEVICE_PUBLIC_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
DEVICE_ID = "dev_grant_events"


def _register_device(account, device_id=DEVICE_ID):
    account.sessions.register_device_key(device_id, INSTALLATION_ID, DEVICE_PUBLIC_KEY)


def _login(account, correlation_id="cor_login"):
    return account.sessions.create_password_session(
        "alice", "password",
        {
            "installationId": INSTALLATION_ID,
            "displayName": "Alice test device",
            "devicePublicKey": DEVICE_PUBLIC_KEY,
        },
        correlation_id,
    )


def _events_of_type(account, event_type):
    return [
        event for event in account.events.read_after(None)
        if event["eventType"] == event_type
    ]


def test_grant_bump_raises_the_revision_monotonically_and_persists(tmp_path):
    """Contract :780 — the revision is monotone, and it survives reopening."""
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        _register_device(account)
        first = account.bump_grant_revision(DEVICE_ID, "cor_bump_first")
        second = account.bump_grant_revision(DEVICE_ID, "cor_bump_second")
        assert first["deviceId"] == DEVICE_ID
        assert (first["grantRevision"], second["grantRevision"]) == (2, 3)
    finally:
        account.close()

    reopened = core.open_gateway_account(ACCOUNT_ID)
    try:
        row = reopened.store.database.execute(
            "SELECT grant_revision FROM device_keys WHERE device_id = ?", (DEVICE_ID,)
        ).fetchone()
        assert row is not None
        assert int(row["grant_revision"]) == 3
    finally:
        reopened.close()


def test_grant_bump_appends_a_schema_valid_pairing_grant_changed_event(tmp_path):
    """Contract :782 — the bump reaches the event stream, payload per $defs."""
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        _register_device(account)
        bumped = account.bump_grant_revision(DEVICE_ID, "cor_grant_event")
    finally:
        account.close()

    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        grant_events = _events_of_type(account, "pairing.grant.changed")
    finally:
        account.close()

    assert len(grant_events) == 1
    event = grant_events[0]
    assert event["correlationId"] == "cor_grant_event"
    # The target device and revision are exact; there are no unknown
    # fields, and the optional fields this Gateway has no real values for are
    # omitted rather than fabricated.
    assert event["payload"] == {"deviceId": DEVICE_ID, "grantRevision": bumped["grantRevision"]}
    contracts = ContractRegistry()
    assert contracts.validate("event.pairingGrantChangedPayload", dict(event["payload"])) is True
    assert contracts.validate("event", {
        "correlationId": event["correlationId"],
        "occurredAt": event["occurredAt"],
        "payload": dict(event["payload"]),
    }) is True


def test_a_claim_carrying_the_pre_bump_revision_answers_grant_stale(tmp_path):
    """Contract :782 — a request carrying the old revision answers GRANT_STALE."""
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        _register_device(account)
        account.bump_grant_revision(DEVICE_ID, "cor_bump_stale")
        enqueue_fixture(account,
            request_id="device_req_grant_stale", device_id=DEVICE_ID,
            pairing_generation=1, grant_revision=2, risk="read",
            capability={"id": "org.openandroidintelligence.sms.query", "version": "1.0.0"},
            provider={"pluginId": "org.openandroidintelligence.sms", "authorKeyId": "sha256:" + "a" * 64},
            parameters={"query": "from:alice"}, correlation_id="cor_enqueue_stale",
        )
        try:
            account.device_requests.claim(
                request_id="device_req_grant_stale", device_id=DEVICE_ID,
                pairing_generation=1, grant_revision=1,
                correlation_id="cor_claim_stale",
            )
        except GatewayError as exc:
            assert exc.code == "GRANT_STALE"
        else:
            raise AssertionError("a claim carrying the pre-bump revision must answer GRANT_STALE")
        claimed = account.device_requests.claim(
            request_id="device_req_grant_stale", device_id=DEVICE_ID,
            pairing_generation=1, grant_revision=2,
            correlation_id="cor_claim_current",
        )
        assert claimed["grantRevision"] == 2
    finally:
        account.close()


def test_grant_bump_writes_audit_for_the_change(tmp_path):
    """Contract :782 — the Gateway records the change (audit), same commit."""
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        _register_device(account)
        account.bump_grant_revision(DEVICE_ID, "cor_bump_audit")

        entries = [
            entry for entry in account.audit.list()
            if entry["eventType"] == "pairing.grant.changed"
        ]
        assert len(entries) == 1
        assert entries[0]["actor"] == {"accountId": ACCOUNT_ID, "deviceId": DEVICE_ID}
        assert entries[0]["subject"] == {"deviceId": DEVICE_ID, "grantRevision": 2}
        assert entries[0]["correlationId"] == "cor_bump_audit"
    finally:
        account.close()


def test_a_failed_commit_leaves_no_revision_no_audit_and_no_event(tmp_path):
    """The bump, the audit row and the stream event are one transaction."""
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        _register_device(account)
        account.store.fail_next_commit = True
        try:
            account.bump_grant_revision(DEVICE_ID, "cor_bump_failed")
        except TransactionOutcomeUnknown:
            pass
        else:
            raise AssertionError("the injected commit failure must surface")
    finally:
        account.close()

    reopened = core.open_gateway_account(ACCOUNT_ID)
    try:
        row = reopened.store.database.execute(
            "SELECT grant_revision FROM device_keys WHERE device_id = ?", (DEVICE_ID,)
        ).fetchone()
        assert int(row["grant_revision"]) == 1
        assert _events_of_type(reopened, "pairing.grant.changed") == []
        assert [
            entry for entry in reopened.audit.list()
            if entry["eventType"] == "pairing.grant.changed"
        ] == []
    finally:
        reopened.close()


def test_admin_grant_bump_is_the_management_plane_entry(tmp_path):
    """The host management surface: gated like pairing.revoke."""
    core = create_gateway_core(storage_root=tmp_path)
    core.open_gateway_account(ACCOUNT_ID).close()
    service = create_admin_service(
        core=core, storage_root=tmp_path, host_version="1.0.0", host_api=TEST_HOST_API
    )
    read_only = create_admin_service(
        core=core, storage_root=tmp_path, host_version="2.0.0", host_api=TEST_HOST_API
    )

    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        _register_device(account)
    finally:
        account.close()

    assert read_only.grant_bump({
        "accountId": ACCOUNT_ID, "deviceId": DEVICE_ID, "localConfirmation": True,
    })["error"]["code"] == "HOST_INCOMPATIBLE"
    assert service.grant_bump({
        "accountId": ACCOUNT_ID, "deviceId": DEVICE_ID,
    })["error"]["code"] == "LOCAL_CONFIRMATION_REQUIRED"
    assert service.grant_bump({
        "accountId": ACCOUNT_ID, "deviceId": "dev_missing!!", "localConfirmation": True,
    })["error"]["code"] == "SCHEMA_INVALID"
    assert service.grant_bump({
        "accountId": ACCOUNT_ID, "deviceId": "dev_absent", "localConfirmation": True,
    })["error"]["code"] == "PAIRING_REQUIRED"

    bumped = service.grant_bump({
        "accountId": ACCOUNT_ID, "deviceId": DEVICE_ID,
        "localConfirmation": True, "correlationId": "cor_admin_bump",
    })
    assert bumped["ok"] is True
    assert bumped["operation"] == "grant.bump"
    assert bumped["data"] == {"deviceId": DEVICE_ID, "grantRevision": 2}

    via_cli = run_admin_command(
        ["grant", "bump", ACCOUNT_ID, DEVICE_ID, "--confirm-local"], service=service
    )
    assert via_cli["ok"] is True, via_cli
    assert via_cli["data"]["grantRevision"] == 3

    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        row = account.store.database.execute(
            "SELECT grant_revision FROM device_keys WHERE device_id = ?", (DEVICE_ID,)
        ).fetchone()
        assert int(row["grant_revision"]) == 3
        assert len(_events_of_type(account, "pairing.grant.changed")) == 2
    finally:
        account.close()


def test_revoking_a_session_appends_a_schema_valid_session_revoked_event(tmp_path):
    """Contract :671 — `session.revoked` rides the event stream, not only audit."""
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        bundle = _login(account, "cor_login")
        account.sessions.revoke_session(bundle["sessionId"], "cor_session_revoke")
        assert account.sessions.resolve_session(
            bundle["accessToken"], bundle["sessionId"], bundle["deviceId"]
        ) is None
    finally:
        account.close()

    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        revoked = _events_of_type(account, "session.revoked")
        assert len(revoked) == 1
        assert revoked[0]["correlationId"] == "cor_session_revoke"
        payload = dict(revoked[0]["payload"])
        assert payload == {"sessionId": bundle["sessionId"], "deviceId": bundle["deviceId"]}
        contracts = ContractRegistry()
        assert contracts.validate("event.sessionRevokedPayload", payload) is True
        assert contracts.validate("event", {
            "correlationId": revoked[0]["correlationId"],
            "occurredAt": revoked[0]["occurredAt"],
            "payload": payload,
        }) is True
        # The pre-existing audit behavior survives untouched.
        audits = [
            entry for entry in account.audit.list()
            if entry["eventType"] == "session.revoked"
        ]
        assert len(audits) == 1
        assert audits[0]["subject"] == {"sessionId": bundle["sessionId"]}
    finally:
        account.close()
