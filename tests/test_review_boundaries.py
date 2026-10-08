from test_support import enqueue_fixture
"""Regression evidence for review H04/H06/H07/M04/M10/M14/M15."""
import json
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from open_android_intelligence_gateway import core as core_module
from open_android_intelligence_gateway.core import GatewayError, create_gateway_core
from test_support import contract_root, make_secret_store

NOW = datetime(2026, 10, 2, tzinfo=timezone.utc)


def negotiate_body(core, negotiation_id="neg_review"):
    body = json.loads((contract_root() / "vectors/protocol-negotiation.json").read_text())["cases"][0]["input"]["value"]
    body["negotiationId"] = negotiation_id
    body["schemaHashes"]["core"] = core.contracts.core_schema_hash
    return body


def test_pending_negotiations_are_bounded_and_retries_keep_absolute_expiry(tmp_path):
    core = create_gateway_core(storage_root=tmp_path, secret_store=make_secret_store())
    def request(identifier, now):
        return core.handle({"method": "POST", "target": "/open-android-intelligence/v2/negotiate", "now": now, "body": negotiate_body(core, identifier)})
    for i in range(1000):
        assert "data" in request(f"neg_{i}", NOW)
    assert request("neg_over", NOW + timedelta(seconds=61))["error"]["code"] == "RATE_LIMITED"
    assert "data" in request("neg_over", NOW + timedelta(seconds=301))
    assert "data" in request("neg_over", NOW + timedelta(seconds=540))
    assert core._pending_negotiations["neg_over"]["expiresAt"] == NOW + timedelta(seconds=601)
    assert len(core._pending_negotiations) == 1


@pytest.mark.parametrize("mutation", ["extra", "missing", "noncanonical", "short", "wrong_type"])
def test_password_schema_is_checked_before_verifier_or_device_registration(tmp_path, mutation):
    core = create_gateway_core(storage_root=tmp_path, secret_store=make_secret_store())
    calls = []
    core.credential_verifier = lambda *args: calls.append(args) or True
    core.open_gateway_account("alice").close()
    core.handle({"method": "POST", "target": "/open-android-intelligence/v2/negotiate", "now": NOW, "body": negotiate_body(core)})
    body = {"negotiationId": "neg_review", "username": "alice", "password": "password", "installation": {
        "installationId": "install_1", "displayName": "Phone", "devicePublicKey": "A" * 43}}
    if mutation == "extra": body["admin"] = True
    elif mutation == "missing": del body["password"]
    elif mutation == "noncanonical": body["installation"]["devicePublicKey"] = "A" * 42 + "B"
    elif mutation == "short": body["installation"]["devicePublicKey"] = "short"
    else: body["installation"]["displayName"] = 12
    response = core.handle({"method": "POST", "target": "/open-android-intelligence/v2/sessions/password", "now": NOW, "body": body})
    assert response["error"]["code"] == "SCHEMA_INVALID"
    assert calls == []
    account = core.open_gateway_account("alice")
    assert account.store.database.execute("SELECT COUNT(*) FROM device_keys").fetchone()[0] == 0
    account.close()


def test_tls_configuration_never_publishes_zero_fingerprint(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    assert core._build_negotiation_response(negotiate_body(core))["gatewayIdentity"]["tlsSpkiSha256"] is None
    pin = "sha256:" + "a" * 64
    core = create_gateway_core(storage_root=tmp_path, tls_spki_sha256=pin)
    assert core._build_negotiation_response(negotiate_body(core))["gatewayIdentity"]["tlsSpkiSha256"] == pin
    with pytest.raises(ValueError, match="GATEWAY_TLS_IDENTITY_INVALID"):
        create_gateway_core(storage_root=tmp_path, tls_spki_sha256="sha256:" + "0" * 64)


def test_event_commit_order_survives_same_millisecond_clock_rollback_restart_and_legacy_migration(tmp_path, monkeypatch):
    core = create_gateway_core(storage_root=tmp_path, secret_store=make_secret_store())
    account = core.open_gateway_account("alice")
    with monkeypatch.context() as context:
        ids = iter(["z", "a", "m"])
        context.setattr(core_module.uuid, "uuid4", lambda: next(ids))
        first = account.events.append("gateway.notice", "cor_1", {"noticeCode": "first"}, NOW)
        second = account.events.append("gateway.notice", "cor_2", {"noticeCode": "second"}, NOW)
        third = account.events.append("gateway.notice", "cor_3", {"noticeCode": "third"}, NOW - timedelta(seconds=1))
    assert [event["eventId"] for event in account.events.read_after(first["eventId"], NOW)] == [second["eventId"], third["eventId"]]
    database_path = account.paths.database
    account.close()
    # Reconstruct the old on-disk layout, preserving actual insertion row order.
    with sqlite3.connect(database_path) as db:
        db.execute("CREATE TABLE legacy_events AS SELECT event_id,event_type,correlation_id,occurred_at,payload_json,expires_at FROM events ORDER BY sequence")
        db.execute("DROP TABLE events")
        db.execute("ALTER TABLE legacy_events RENAME TO events")
    account = core.open_gateway_account("alice")
    assert [event["eventId"] for event in account.events.read_after(first["eventId"], NOW)] == [second["eventId"], third["eventId"]]
    assert account.events.read_after(None, NOW + timedelta(days=2)) == []
    assert account.store.database.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
    with pytest.raises(GatewayError, match="CURSOR_EXPIRED"):
        account.events.read_after(first["eventId"], NOW + timedelta(days=2))
    account.close()


def test_message_and_result_payloads_are_encrypted_and_terminal_inputs_are_erased(tmp_path):
    core = create_gateway_core(storage_root=tmp_path, secret_store=make_secret_store())
    account = core.open_gateway_account("alice")
    conversation = account.conversations.create("client_review", None, "cor_conv", NOW)
    message = account.conversations.accept_message(conversation["conversationId"], "client_msg", "private-message-marker", [], "dev_1", "req_msg", "cor_msg", NOW)
    row = account.store.database.execute("SELECT text FROM messages").fetchone()
    assert "private-message-marker" not in row[0]
    assert account.conversations.dispatch_message("client_msg")["text"] == "private-message-marker"
    enqueue_fixture(account, request_id="dr_review", device_id="dev_1", pairing_generation=1, grant_revision=1, risk="read",
        capability={"id": "org.openandroidintelligence.sms.query", "version": "1.0.0"},
        provider={"pluginId": "org.openandroidintelligence.sms", "authorKeyId": "sha256:" + "a" * 64},
        parameters={"query": "private-input-marker"}, correlation_id="cor_device", now=NOW)
    receipt = account.device_requests.claim("dr_review", "dev_1", 1, 1, "cor_claim", NOW)
    result = {"outcome": "succeeded", "data": {"marker": "private-result-marker"}}
    account.device_requests.submit_result("dr_review", "dev_1", 1, 1, receipt["claimId"], result, "cor_result", NOW)
    row = account.store.database.execute("SELECT parameters_json,result_json FROM device_requests").fetchone()
    assert row[0] == "" and "private-result-marker" not in row[1]
    assert account.device_requests.read_result("dr_review", receipt["claimId"], NOW) == result
    account.device_requests.acknowledge_result("dr_review", receipt["claimId"])
    assert account.device_requests.read_result("dr_review", receipt["claimId"], NOW) is None
    account.close()


def test_plaintext_message_migration_scrubs_sqlite_and_wal_and_recovers_after_busy_reader(tmp_path):
    core = create_gateway_core(storage_root=tmp_path, secret_store=make_secret_store())
    account = core.open_gateway_account("alice")
    conversation = account.conversations.create("legacy_conv", None, "cor_legacy", NOW)
    account.conversations.accept_message(conversation["conversationId"], "legacy_msg", "legacy-private-marker-retain-this-message", [], "dev_1", "req_1", "cor_legacy", NOW)
    path = account.paths.database
    account.store.database.execute("UPDATE messages SET text = ?", ("legacy-private-marker-retain-this-message",))
    account.store.database.execute("DELETE FROM account_metadata WHERE key = 'message_storage_format'")
    account.store.database.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    account.close()
    assert b"legacy-private-marker" in path.read_bytes()
    reader = sqlite3.connect(path, isolation_level=None)
    reader.execute("BEGIN")
    reader.execute("SELECT * FROM messages").fetchall()
    try:
        with pytest.raises(GatewayError, match="MESSAGE_MIGRATION_BUSY"):
            core.open_gateway_account("alice")
    finally:
        reader.execute("ROLLBACK")
        reader.close()
    account = core.open_gateway_account("alice")
    assert account.conversations.dispatch_message("legacy_msg")["text"] == "legacy-private-marker-retain-this-message"
    assert account.store.database.execute("SELECT 1 FROM account_metadata WHERE key = 'message_scrub_pending'").fetchone() is None
    account.close()
    for file in (path, Path(str(path) + "-wal")):
        if file.exists():
            assert b"legacy-private-marker" not in file.read_bytes()
