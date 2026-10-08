from test_support import enqueue_fixture
import sys
import hashlib
import json
import shutil
import sqlite3
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from open_android_intelligence_gateway.account_paths import account_paths
from open_android_intelligence_gateway.core import (
    GatewayError,
    GatewayResponse,
    ContractRegistry,
    SHARED_VECTOR_FILE_NAMES,
    VerifiedGatewayRequest,
    VerifiedRequestContext,
    create_gateway_core,
)
from open_android_intelligence_gateway.audit import AuditStore
from open_android_intelligence_gateway.http import DEFAULT_MAX_BODY_BYTES
from open_android_intelligence_gateway.plugin import register
from test_support import contract_root, core_schema_hash, make_secret_store, trust_core


_real_create_gateway_core = create_gateway_core


def create_gateway_core(storage_root=None, **options):
    options.setdefault("secret_store", make_secret_store())
    return trust_core(_real_create_gateway_core(storage_root=storage_root, **options))


class FakeHermesContext:
    def __init__(self, plugin_data_dir):
        self.plugin_data_dir = plugin_data_dir
        self.secret_store = None
        self.platform_ids = []
        self.admin_surfaces = []

    def register_platform(self, platform):
        self.platform_ids.append(platform.platform_id)

    def register_admin(self, admin):
        self.admin_surfaces.append(admin)


def test_registers_gateway_platform(tmp_path):
    context = FakeHermesContext(tmp_path)

    register(context)

    assert context.platform_ids == ["open-android-intelligence-gateway"]


def test_accounts_never_share_database(tmp_path):
    alice = account_paths(tmp_path, "alice")
    bob = account_paths(tmp_path, "bob")

    assert alice.database != bob.database


def _context(**overrides):
    context = {
        "accountId": "acct_alice",
        "deviceId": "dev_1",
        "sessionId": "sess_1",
        "requestId": "req_1",
        "correlationId": "cor_1",
        "pairingGeneration": 1,
        "grantRevision": 1,
    }
    context.update(overrides)
    return context


def test_account_state_and_event_cursors_never_cross_databases(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    alice = core.open_gateway_account("acct_alice")
    bob = core.open_gateway_account("acct_bob")

    event = alice.events.append(
        event_type="gateway.notice",
        correlation_id="cor_alice",
        payload={"noticeCode": "ready"},
    )
    assert event["eventId"]
    assert event["eventId"] in [item["eventId"] for item in alice.events.read_after(None)]
    try:
        bob.events.read_after(event["eventId"])
    except GatewayError as exc:
        assert exc.code == "CURSOR_EXPIRED"
    else:
        raise AssertionError("Bob must not read Alice's cursor")

    conversation = bob.conversations.create(
        client_conversation_id="conv_bob",
        title="Bob",
        correlation_id="cor_bob",
    )
    try:
        bob.conversations.accept_message(
            conversation_id=conversation["conversationId"],
            client_message_id="msg_bob",
            text="do not retain this body",
            attachment_ids=["att_alice"],
            device_id="dev_bob",
            request_id="req_bob",
            correlation_id="cor_bob_message",
        )
    except GatewayError as exc:
        assert exc.code == "ATTACHMENT_EXPIRED"
    else:
        raise AssertionError("Bob must not reference Alice's attachment")
    assert "do not retain this body" not in str(bob.audit.list())


def test_handle_enforces_identity_idempotency_and_sse_cursor_binding(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_alice")
    old_event = account.events.append(
        event_type="gateway.notice",
        correlation_id="cor_old",
        payload={"noticeCode": "old"},
    )
    account.close()

    identity = core.handle(
        {
            "context": _context(requestId="req_identity"),
            "method": "POST",
            "target": "/open-android-intelligence/v2/conversations",
            "idempotencyKey": "req_identity",
            "body": {"clientConversationId": "conv_identity", "accountId": "acct_bob"},
        }
    )
    assert identity["error"]["code"] == "IDENTITY_OVERRIDE_REJECTED"

    request = {
        "context": _context(requestId="req_create", correlationId="cor_create"),
        "method": "POST",
        "target": "/open-android-intelligence/v2/conversations",
        "idempotencyKey": "req_create",
        "body": {"clientConversationId": "conv_create", "title": "A"},
    }
    first = core.handle(request)
    assert first["data"]["conversation"]["clientConversationId"] == "conv_create"
    assert core.handle(request) == first
    conflict = core.handle({**request, "body": {"clientConversationId": "conv_changed"}})
    assert conflict["error"]["code"] == "IDEMPOTENCY_CONFLICT"

    cursor_conflict = core.handle(
        {
            "context": _context(requestId="req_cursor"),
            "method": "GET",
            "target": f"/open-android-intelligence/v2/events?cursor={old_event['eventId']}",
            "lastEventId": "evt_other",
        }
    )
    assert cursor_conflict["error"]["code"] == "CURSOR_CONFLICT"


def test_consumes_the_shared_schema_and_vector_registry(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)

    results = core.run_shared_vectors()
    vector_root = contract_root() / "vectors"
    contract_files = set(SHARED_VECTOR_FILE_NAMES)
    discovered = {
        path.name for path in vector_root.glob("*.json")
        if not path.name.endswith(".schema.json") and path.name != "dispatched-schema-fixtures.json"
    }
    cases = [
        case for name in SHARED_VECTOR_FILE_NAMES
        for case in json.loads((vector_root / name).read_text(encoding="utf-8"))["cases"]
    ]

    # Contract section 16 enumerates exactly six shared vector documents and a
    # closed `schemaName` set; the conversation-UI document is a local suite.
    assert contract_files <= discovered
    assert discovered - contract_files == {"conversation-ui.json"}
    # The shared Protocol 2.1 fixture set adds two independent message-status
    # cases to the prior vectors, including the failed/errorCode distinction.
    assert len(cases) == 66
    assert len({case["id"] for case in cases}) == 66
    assert len(results) == 66
    assert {result["status"] for result in results} == {"pass"}
    assert {result["implementation"] for result in results} == {"hermes-python"}


def test_attachment_staging_is_account_local_and_expires_after_ack_or_ttl(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    alice = core.open_gateway_account("acct_alice")
    bob = core.open_gateway_account("acct_bob")
    body = b"short lived content"
    digest = hashlib.sha256(body).hexdigest()

    attachment = alice.attachments.create(
        client_attachment_id="att_client_1",
        filename="note.txt",
        media_type="text/plain",
        size_bytes=len(body),
        sha256=digest,
        correlation_id="cor_attachment",
    )
    alice.attachments.upload_content(attachment["attachmentId"], body)
    verified = alice.attachments.commit(attachment["attachmentId"])
    assert verified["status"] == "uploaded"
    assert alice.attachments.get_record(attachment["attachmentId"])["hasStagedBytes"] is True
    try:
        bob.attachments.get(attachment["attachmentId"])
    except GatewayError as exc:
        assert exc.code == "ATTACHMENT_EXPIRED"
    else:
        raise AssertionError("Bob must not read Alice's staged attachment")

    alice.attachments.mark_delivered(attachment["attachmentId"])
    acknowledged = alice.attachments.acknowledge(attachment["attachmentId"], "cor_ack")
    assert acknowledged["status"] == "uploaded"
    assert alice.attachments.get_record(attachment["attachmentId"])["hasStagedBytes"] is False
    ack_events = alice.events.read_after(None)
    assert [event["eventType"] for event in ack_events] == ["attachment.acknowledged"]
    assert ack_events[0]["payload"] == {"attachmentId": attachment["attachmentId"]}

    expiring = alice.attachments.create(
        client_attachment_id="att_client_2",
        filename="ttl.txt",
        media_type="text/plain",
        size_bytes=len(body),
        sha256=digest,
        correlation_id="cor_ttl",
        now="2030-01-01T00:00:00.000Z",
        expires_at="2030-01-01T01:00:00.000Z",
    )
    alice.attachments.upload_content(expiring["attachmentId"], body)
    assert alice.attachments.expire_due("2030-01-01T01:00:01.000Z") == 1
    assert alice.attachments.get(expiring["attachmentId"])["status"] == "expired"
    assert alice.attachments.get_record(expiring["attachmentId"])["hasStagedBytes"] is False


def test_attachment_digest_failure_is_rejected_before_a_stage_is_published(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_alice")
    body = b"digest failure body"
    attachment = account.attachments.create(
        client_attachment_id="att_digest",
        filename="digest.txt",
        media_type="text/plain",
        size_bytes=len(body),
        sha256=hashlib.sha256(b"different").hexdigest(),
        correlation_id="cor_digest",
    )
    with pytest.raises(GatewayError) as error:
        account.attachments.upload_content(attachment["attachmentId"], body)
    assert error.value.code == "ATTACHMENT_DIGEST_MISMATCH"
    failed = account.attachments.get_record(attachment["attachmentId"])
    assert failed["status"] == "staged"
    assert failed["hasStagedBytes"] is False

    # A mismatching signed upload never reaches the persisted stage, so there is
    # nothing for cleanup to delete and the client may retry with correct bytes.
    try:
        account.attachments.commit(attachment["attachmentId"])
    except GatewayError as exc:
        assert exc.code == "ATTACHMENT_EXPIRED"
    else:
        raise AssertionError("A missing stage must not be treated as verified")


def test_attachment_reconciliation_recovers_an_orphaned_stage_for_the_same_account(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_alice")
    body = b"recoverable stage"
    attachment = account.attachments.create(
        client_attachment_id="att_recover",
        filename="recover.txt",
        media_type="text/plain",
        size_bytes=len(body),
        sha256=hashlib.sha256(body).hexdigest(),
        correlation_id="cor_recover",
        now="2030-01-01T00:00:00.000Z",
        expires_at="2030-01-01T00:10:00.000Z",
    )
    stage_path = account.paths.attachments / f"{attachment['attachmentId']}.stage"
    stage_path.write_bytes(body)

    assert account.attachments.cleanup() == 0
    assert account.attachments.get(attachment["attachmentId"])["status"] == "staged"
    assert account.attachments.get_record(attachment["attachmentId"])["hasStagedBytes"] is True
    assert account.attachments.expire_due("2030-01-01T00:10:01.000Z") == 1
    assert account.attachments.get_record(attachment["attachmentId"])["hasStagedBytes"] is False


def test_attachment_reconciliation_failure_protects_stage_until_next_scan(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_alice")
    body = b"reconciliation must fail closed"
    attachment = account.attachments.create(
        client_attachment_id="att_reconcile_protected",
        filename="reconcile.txt",
        media_type="text/plain",
        size_bytes=len(body),
        sha256=hashlib.sha256(body).hexdigest(),
        correlation_id="cor_reconcile",
        now="2030-01-01T00:00:00.000Z",
        expires_at="2030-01-01T00:10:00.000Z",
    )
    stage_path = account.paths.attachments / f"{attachment['attachmentId']}.stage"
    stage_path.write_bytes(body)
    account.store.database.execute(
        f"""
        CREATE TRIGGER fail_reconcile
        BEFORE UPDATE OF state, content_path ON attachments
        WHEN OLD.attachment_id = '{attachment['attachmentId']}'
          AND OLD.content_path IS NULL AND NEW.content_path IS NOT NULL
        BEGIN SELECT RAISE(ABORT, 'reconciliation forced failure'); END;
        """
    )

    assert account.attachments.cleanup() == 0
    assert stage_path.exists()
    assert account.attachments.get(attachment["attachmentId"])["status"] == "staged"
    account.store.database.execute("DROP TRIGGER fail_reconcile")
    assert account.attachments.cleanup() == 0
    assert account.attachments.get(attachment["attachmentId"])["status"] == "staged"
    assert account.attachments.expire_due("2030-01-01T00:10:01.000Z") == 1
    assert not stage_path.exists()


def test_attachment_cas_is_not_removed_while_another_account_local_attachment_references_it(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_alice")
    body = b"same content address"
    digest = hashlib.sha256(body).hexdigest()
    first = account.attachments.create(
        client_attachment_id="att_cas_1", filename="one.txt", media_type="text/plain",
        size_bytes=len(body), sha256=digest, correlation_id="cor_cas_1",
    )
    second = account.attachments.create(
        client_attachment_id="att_cas_2", filename="two.txt", media_type="text/plain",
        size_bytes=len(body), sha256=digest, correlation_id="cor_cas_2",
    )
    for item in (first, second):
        account.attachments.upload_content(item["attachmentId"], body)
        account.attachments.commit(item["attachmentId"])
        account.attachments.mark_delivered(item["attachmentId"])
    account.attachments.acknowledge(first["attachmentId"], "cor_cas_ack")
    assert account.attachments.get_record(second["attachmentId"])["hasStagedBytes"] is True


def _attachment_input(client_id="att_policy", media_type="text/plain", size_bytes=4):
    return {
        "client_attachment_id": client_id,
        "filename": "policy.txt",
        "media_type": media_type,
        "size_bytes": size_bytes,
        "sha256": hashlib.sha256(b"data").hexdigest(),
        "correlation_id": "cor_policy",
        "now": "2030-01-01T00:00:00.000Z",
    }


def _force_attachment_expired(account, attachment_id):
    account.store.database.execute(
        "UPDATE attachments SET expires_at = ?, storage_revision = storage_revision + 1 WHERE attachment_id = ?",
        ("2000-01-01T00:00:00.000Z", attachment_id),
    )


def test_attachment_metadata_has_no_product_size_or_media_allowlist_but_keeps_ttl(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_policy")

    large_and_custom = account.attachments.create(
        **_attachment_input(
            "att_large_custom", size_bytes=52_428_801,
            media_type="application/x-executable",
        )
    )
    assert large_and_custom["sizeBytes"] == 52_428_801
    assert account.attachments.get_record(large_and_custom["attachmentId"])["mediaType"] == "application/x-executable"

    with pytest.raises(GatewayError) as ttl_bypass:
        account.attachments.create(
            **_attachment_input("att_ttl_bypass"),
            expires_at="2026-08-29T00:00:00.000Z",
        )
    assert ttl_bypass.value.code == "SCHEMA_INVALID"
    assert DEFAULT_MAX_BODY_BYTES < 26_214_400


def test_expired_attachment_is_rejected_at_upload_commit_read_and_message_reference(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_policy_expiry")
    body = b"data"

    upload_late = account.attachments.create(**_attachment_input("att_upload_late"))
    _force_attachment_expired(account, upload_late["attachmentId"])
    with pytest.raises(GatewayError) as late_upload:
        account.attachments.upload_content(upload_late["attachmentId"], body)
    assert late_upload.value.code == "ATTACHMENT_EXPIRED"
    late_read = account.attachments.get(upload_late["attachmentId"])
    assert late_read["status"] == "expired"
    assert account.attachments.get_record(upload_late["attachmentId"])["hasStagedBytes"] is False

    late_commit = account.attachments.create(**_attachment_input("att_commit_late"))
    account.attachments.upload_content(late_commit["attachmentId"], body)
    _force_attachment_expired(account, late_commit["attachmentId"])
    with pytest.raises(GatewayError) as commit_error:
        account.attachments.commit(late_commit["attachmentId"])
    assert commit_error.value.code == "ATTACHMENT_EXPIRED"

    late_message = account.attachments.create(**_attachment_input("att_message_late"))
    account.attachments.upload_content(late_message["attachmentId"], body)
    account.attachments.commit(late_message["attachmentId"])
    _force_attachment_expired(account, late_message["attachmentId"])
    with pytest.raises(GatewayError) as message_error:
        account.attachments.require_verified_for_message(late_message["attachmentId"])
    assert message_error.value.code == "ATTACHMENT_EXPIRED"


def _device_input(request_id, risk="read", now="2026-08-24T12:00:00.000Z"):
    return {
        "request_id": request_id,
        "device_id": "dev_1",
        "pairing_generation": 4,
        "grant_revision": 7,
        "risk": risk,
        "capability": {"id": "org.openandroidintelligence.sms.query", "version": "1.0.0"},
        "provider": {
            "pluginId": "org.openandroidintelligence.sms",
            "authorKeyId": "sha256:" + "a" * 64,
        },
        "parameters": {"query": "from:alice"},
        "correlation_id": "cor_device",
        "now": now,
    }


def test_device_claim_result_is_bound_and_recoverable_per_account(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    alice = core.open_gateway_account("acct_alice")
    bob = core.open_gateway_account("acct_bob")
    read = enqueue_fixture(alice, **_device_input("device_req_read"))
    write = enqueue_fixture(alice, **_device_input("device_req_write", "write"))
    high = enqueue_fixture(alice, **_device_input("device_req_high", "high-privilege-ephemeral"))

    assert read["expiresAt"] == "2026-08-25T12:00:00.000Z"
    assert write["expiresAt"] == "2026-08-24T12:15:00.000Z"
    assert high["state"] == "expired"

    try:
        alice.device_requests.submit_result(
            request_id="device_req_read", device_id="dev_1", pairing_generation=4,
            grant_revision=7, claim_id="missing", result={"outcome": "succeeded"},
            correlation_id="cor_unclaimed", now="2026-08-24T12:01:00.000Z",
        )
    except GatewayError as exc:
        assert exc.code == "OUTCOME_UNKNOWN"
    else:
        raise AssertionError("An unclaimed request cannot accept a result")

    claim = alice.device_requests.claim(
        request_id="device_req_read", device_id="dev_1", pairing_generation=4,
        grant_revision=7, correlation_id="cor_claim", now="2026-08-24T12:02:00.000Z",
    )
    assert alice.device_requests.claim(
        request_id="device_req_read", device_id="dev_1", pairing_generation=4,
        grant_revision=7, correlation_id="cor_claim_retry", now="2026-08-24T12:03:00.000Z",
    ) == claim
    try:
        alice.device_requests.claim(
            request_id="device_req_read", device_id="dev_2", pairing_generation=4,
            grant_revision=7, correlation_id="cor_wrong_device", now="2026-08-24T12:04:00.000Z",
        )
    except GatewayError as exc:
        assert exc.code == "PAIRING_GENERATION_STALE"
    else:
        raise AssertionError("A claim must remain device-bound")
    try:
        alice.device_requests.claim(
            request_id="device_req_read", device_id="dev_1", pairing_generation=4,
            grant_revision=8, correlation_id="cor_wrong_grant", now="2026-08-24T12:04:00.000Z",
        )
    except GatewayError as exc:
        assert exc.code == "GRANT_STALE"
    else:
        raise AssertionError("A claim must remain grant-bound")
    try:
        bob.device_requests.submit_result(
            request_id="device_req_read", device_id="dev_1", pairing_generation=4,
            grant_revision=7, claim_id=claim["claimId"], result={"outcome": "succeeded"},
            correlation_id="cor_cross_account", now="2026-08-24T12:04:00.000Z",
        )
    except GatewayError as exc:
        assert exc.code == "OUTCOME_UNKNOWN"
    else:
        raise AssertionError("A claim receipt must not cross account databases")

    result = alice.device_requests.submit_result(
        request_id="device_req_read", device_id="dev_1", pairing_generation=4,
        grant_revision=7, claim_id=claim["claimId"], result={"outcome": "succeeded", "data": {"ok": True}},
        correlation_id="cor_result", now="2026-08-24T12:05:00.000Z",
    )
    assert result["state"] == "succeeded"
    alice.device_requests.claim(
        request_id="device_req_write", device_id="dev_1", pairing_generation=4,
        grant_revision=7, correlation_id="cor_claim_write", now="2026-08-24T12:05:00.000Z",
    )
    alice.close()
    reopened = core.open_gateway_account("acct_alice")
    assert reopened.device_requests.recover_expired("2026-08-24T12:16:00.000Z") == 1
    assert reopened.device_requests.get("device_req_write")["state"] == "outcome_unknown"


def test_device_request_expiry_is_enforced_at_claim_and_result_entry(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_alice")
    enqueue_fixture(account, **_device_input("device_req_expired", "write", "2026-08-27T00:00:00.000Z"))

    try:
        account.device_requests.claim(
            request_id="device_req_expired", device_id="dev_1", pairing_generation=4,
            grant_revision=7, correlation_id="cor_late_claim", now="2026-08-27T00:16:00.000Z",
        )
    except GatewayError as exc:
        assert exc.code == "OUTCOME_UNKNOWN"
    else:
        raise AssertionError("Late claim must not execute")
    assert account.device_requests.get("device_req_expired")["state"] == "expired"


def test_gateway_core_handle_routes_attachment_and_device_claim_result(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    body = b"handle-owned staged bytes"
    create = core.handle({
        "context": _context(requestId="req_attachment_create", correlationId="cor_attachment_create"),
        "method": "POST",
        "target": "/open-android-intelligence/v2/attachments",
        "idempotencyKey": "req_attachment_create",
        "body": {
            "clientAttachmentId": "att_client_handle",
            "filename": "handle.txt",
            "mediaType": "text/plain",
            "sizeBytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
        },
    })
    assert "attachment" in create["data"]
    attachment_id = create["data"]["attachment"]["attachmentId"]
    uploaded = core.handle({
        "context": _context(requestId="req_attachment_upload", correlationId="cor_attachment_upload"),
        "method": "PUT",
        "target": f"/open-android-intelligence/v2/attachments/{attachment_id}/content",
        "idempotencyKey": "req_attachment_upload",
        "body": body,
    })
    assert uploaded["data"]["attachment"]["status"] == "staged"
    committed = core.handle({
        "context": _context(requestId="req_attachment_commit", correlationId="cor_attachment_commit"),
        "method": "POST",
        "target": f"/open-android-intelligence/v2/attachments/{attachment_id}/commit",
        "idempotencyKey": "req_attachment_commit",
    })
    assert committed["data"]["attachment"]["status"] == "uploaded"

    retried_create = core.handle({
        "context": _context(requestId="req_attachment_create_retry", correlationId="cor_attachment_create_retry"),
        "method": "POST",
        "target": "/open-android-intelligence/v2/attachments",
        "idempotencyKey": "req_attachment_create_retry",
        "body": {
            "clientAttachmentId": "att_client_handle",
            "filename": "handle.txt",
            "mediaType": "text/plain",
            "sizeBytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
        },
    })
    assert retried_create["data"]["attachment"]["attachmentId"] == attachment_id
    assert retried_create["data"]["attachment"]["status"] == "uploaded"

    conflicting_create = core.handle({
        "context": _context(requestId="req_attachment_create_conflict", correlationId="cor_attachment_create_conflict"),
        "method": "POST",
        "target": "/open-android-intelligence/v2/attachments",
        "idempotencyKey": "req_attachment_create_conflict",
        "body": {
            "clientAttachmentId": "att_client_handle",
            "filename": "different.txt",
            "mediaType": "text/plain",
            "sizeBytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
        },
    })
    assert conflicting_create["error"]["code"] == "IDEMPOTENCY_CONFLICT"

    recovered_status = core.handle({
        "context": _context(requestId="req_attachment_status", correlationId="cor_attachment_status"),
        "method": "GET",
        "target": f"/open-android-intelligence/v2/attachments/{attachment_id}",
    })
    assert recovered_status["data"]["attachment"] == {
        "attachmentId": attachment_id,
        "status": "uploaded",
        "sizeBytes": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
    }

    account = core.open_gateway_account("acct_alice")
    enqueue_fixture(account, **_device_input("device_req_handle", now="2026-08-27T00:00:00.000Z"))
    account.close()
    claim = core.handle({
        "context": _context(requestId="req_claim_handle", correlationId="cor_claim_handle", pairingGeneration=4, grantRevision=7),
        "method": "POST",
        "target": "/open-android-intelligence/v2/device-requests/device_req_handle/claim",
        "idempotencyKey": "req_claim_handle",
        "now": "2026-08-27T00:01:00.000Z",
    })
    assert claim["data"]["grantRevision"] == 7
    receipt = claim["data"]
    stale = core.handle({
        "context": _context(requestId="req_result_stale", correlationId="cor_result_stale", pairingGeneration=4, grantRevision=8),
        "method": "POST",
        "target": "/open-android-intelligence/v2/device-requests/device_req_handle/result",
        "idempotencyKey": "req_result_stale",
        "body": {
            "claimId": receipt["claimId"],
            "grantRevision": 7,
            "result": {"outcome": "succeeded", "data": {"ok": True}},
        },
        "now": "2026-08-27T00:02:00.000Z",
    })
    assert stale["error"]["code"] == "GRANT_STALE"
    result = core.handle({
        "context": _context(requestId="req_result_handle", correlationId="cor_result_handle", pairingGeneration=4, grantRevision=7),
        "method": "POST",
        "target": "/open-android-intelligence/v2/device-requests/device_req_handle/result",
        "idempotencyKey": "req_result_handle",
        "body": {
            "claimId": receipt["claimId"],
            "grantRevision": 7,
            "result": {"outcome": "succeeded", "data": {"ok": True}},
        },
        "now": "2026-08-27T00:02:00.000Z",
    })
    assert result["data"]["deviceRequest"]["state"] == "succeeded"


def test_invalid_state_transition_is_not_exposed_or_persisted_as_wire_error(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    body = b"invalid state boundary"
    create = core.handle({
        "context": _context(requestId="req_invalid_state_create", correlationId="cor_invalid_state_create"),
        "method": "POST", "target": "/open-android-intelligence/v2/attachments",
        "idempotencyKey": "req_invalid_state_create",
        "body": {
            "clientAttachmentId": "att_invalid_state",
            "filename": "invalid-state.txt", "mediaType": "text/plain",
            "sizeBytes": len(body), "sha256": hashlib.sha256(body).hexdigest(),
        },
    })
    attachment_id = create["data"]["attachment"]["attachmentId"]
    core.handle({
        "context": _context(requestId="req_invalid_state_upload", correlationId="cor_invalid_state_upload"),
        "method": "PUT", "target": f"/open-android-intelligence/v2/attachments/{attachment_id}/content",
        "idempotencyKey": "req_invalid_state_upload", "body": body,
    })
    first_commit = core.handle({
        "context": _context(requestId="req_invalid_state_commit", correlationId="cor_invalid_state_commit"),
        "method": "POST", "target": f"/open-android-intelligence/v2/attachments/{attachment_id}/commit",
        "idempotencyKey": "req_invalid_state_commit",
    })
    assert first_commit["data"]["attachment"]["status"] == "uploaded"

    repeated_commit = core.handle({
        "context": _context(requestId="req_invalid_state_repeat", correlationId="cor_invalid_state_repeat"),
        "method": "POST", "target": f"/open-android-intelligence/v2/attachments/{attachment_id}/commit",
        "idempotencyKey": "req_invalid_state_repeat",
    })
    assert repeated_commit["error"]["code"] == "SCHEMA_INVALID"
    account = core.open_gateway_account("acct_alice")
    ledger = account.store.database.execute(
        "SELECT outcome_json FROM idempotency_ledger WHERE request_id = 'req_invalid_state_repeat'"
    ).fetchone()
    assert ledger is None
    account.close()


def test_core_rejects_untrusted_mapping_and_missing_verified_binding_fields(tmp_path):
    core = _real_create_gateway_core(storage_root=tmp_path, secret_store=make_secret_store())
    request = {
        "context": _context(requestId="req_untrusted_mapping"),
        "method": "POST", "target": "/open-android-intelligence/v2/conversations",
        "idempotencyKey": "req_untrusted_mapping",
        "body": {"clientConversationId": "conv_untrusted_mapping"},
    }

    untrusted = core.handle(request)
    missing_binding = core.handle({
        **request,
        "context": {
            "accountId": "acct_alice", "deviceId": "dev_1", "sessionId": "sess_1",
            "requestId": "req_missing_binding", "correlationId": "cor_missing_binding",
        },
        "idempotencyKey": "req_missing_binding",
    })

    assert untrusted["error"]["code"] == "AUTHENTICATION_REQUIRED"
    assert missing_binding["error"]["code"] == "AUTHENTICATION_REQUIRED"


def test_typed_verified_request_and_response_surfaces_keep_camel_case_protocol_names(tmp_path):
    context = VerifiedRequestContext(
        accountId="acct_alice", deviceId="dev_1", sessionId="sess_1",
        requestId="req_typed", correlationId="cor_typed",
        pairingGeneration=1, grantRevision=1,
    )
    request = VerifiedGatewayRequest(
        context=context, method="POST", target="/open-android-intelligence/v2/conversations",
        idempotencyKey="req_typed", body={"clientConversationId": "conv_typed"},
    )
    response = create_gateway_core(storage_root=tmp_path).handle(request)

    assert isinstance(response, GatewayResponse)
    assert response.data["conversation"]["clientConversationId"] == "conv_typed"
    assert response.requestId == "req_typed"
    with pytest.raises(TypeError):
        request.body["clientConversationId"] = "mutated"


def test_gateway_response_and_nested_data_are_immutable_across_idempotent_replay(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    request = {
        "context": _context(requestId="req_immutable_response"),
        "method": "POST", "target": "/open-android-intelligence/v2/conversations",
        "idempotencyKey": "req_immutable_response",
        "body": {"clientConversationId": "conv_immutable_response", "title": "stable"},
    }
    response = core.handle(request)

    with pytest.raises(TypeError):
        response["extra"] = True
    with pytest.raises(TypeError):
        response["data"]["conversation"]["title"] = "mutated"

    assert core.handle(request) == response


def test_gateway_core_negotiates_the_shared_protocol_schema_and_feature_intersection(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    response = core.handle({
        "context": _context(requestId="req_negotiate", correlationId="cor_negotiate"),
        "method": "POST",
        "target": "/open-android-intelligence/v2/negotiate",
        "idempotencyKey": "req_negotiate",
        "body": {
            "negotiationId": "neg_1",
            "protocol": {"major": 2, "minor": 1},
            "client": {"installationId": "install_1", "appVersion": "2.0.0", "platform": "android", "platformApi": 35},
            "features": {
                "auth": ["password", "refresh"], "messages": ["chat-v1"],
                "attachments": ["staged-sha256-v1"], "events": ["sse-cursor-v1"],
                "deviceRequests": ["risk-queue-v1"],
            },
            "schemaHashes": {"core": core_schema_hash()},
        },
    })

    assert response["data"]["protocol"] == {"major": 2, "minor": 1}
    assert response["data"]["features"]["auth"] == ["password", "refresh"]
    assert response["data"]["features"]["messages"] == "chat-v1"
    assert response["data"]["limits"]["attachmentTtlSeconds"] == 3600
    assert response["data"]["gatewayIdentity"]["deploymentId"]


def test_gateway_core_serves_account_local_conversation_reads(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    created = core.handle({
        "context": _context(requestId="req_read_create"),
        "method": "POST", "target": "/open-android-intelligence/v2/conversations",
        "idempotencyKey": "req_read_create",
        "body": {"clientConversationId": "conv_read"},
    })
    conversation_id = created["data"]["conversation"]["conversationId"]
    listed = core.handle({
        "context": _context(requestId="req_read_list"),
        "method": "GET", "target": "/open-android-intelligence/v2/conversations",
    })
    fetched = core.handle({
        "context": _context(requestId="req_read_fetch"),
        "method": "GET", "target": f"/open-android-intelligence/v2/conversations/{conversation_id}",
    })

    assert listed["data"]["conversations"][0]["conversationId"] == conversation_id
    assert fetched["data"]["conversation"]["clientConversationId"] == "conv_read"


def test_idempotency_expiry_and_replay_binding_fail_closed(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    request = {
        "context": _context(requestId="req_expiring", correlationId="cor_expiring"),
        "method": "POST", "target": "/open-android-intelligence/v2/conversations",
        "idempotencyKey": "req_expiring",
        "body": {"clientConversationId": "conv_expiring"},
        "now": "2026-08-27T00:00:00.000Z",
    }
    first = core.handle(request)
    assert first["data"]["conversation"]
    account = core.open_gateway_account("acct_alice")
    account.store.database.execute(
        "UPDATE idempotency_ledger SET expires_at = ? WHERE device_id = ? AND request_id = ?",
        ("2026-08-27T00:00:01.000Z", "dev_1", "req_expiring"),
    )
    account.close()
    expired = core.handle({**request, "now": "2026-08-27T00:00:02.000Z"})
    assert expired["error"]["code"] == "OUTCOME_UNKNOWN"

    account = core.open_gateway_account("acct_alice")
    enqueue_fixture(account, **_device_input("device_req_replay", now="2026-08-27T00:00:00.000Z"))
    account.close()
    claim = core.handle({
        "context": _context(requestId="req_claim_replay", correlationId="cor_claim_replay", pairingGeneration=4, grantRevision=7),
        "method": "POST", "target": "/open-android-intelligence/v2/device-requests/device_req_replay/claim",
        "idempotencyKey": "req_claim_replay", "now": "2026-08-27T00:01:00.000Z",
    })
    assert claim["data"]
    stale_replay = core.handle({
        "context": _context(requestId="req_claim_replay", correlationId="cor_claim_replay", pairingGeneration=5, grantRevision=7),
        "method": "POST", "target": "/open-android-intelligence/v2/device-requests/device_req_replay/claim",
        "idempotencyKey": "req_claim_replay", "now": "2026-08-27T00:01:01.000Z",
    })
    assert stale_replay["error"]["code"] == "PAIRING_GENERATION_STALE"

    old = core.open_gateway_account("acct_bob")
    event = old.events.append("gateway.notice", "cor_old", {"noticeCode": "old"}, "2026-08-24T00:00:00.000Z")
    old.close()
    cursor_expired = core.handle({
        "context": _context(accountId="acct_bob", requestId="req_cursor_expired"),
        "method": "GET", "target": f"/open-android-intelligence/v2/events?cursor={event['eventId']}",
        "lastEventId": event["eventId"], "now": "2026-08-25T00:00:01.000Z",
    })
    assert cursor_expired["error"]["code"] == "CURSOR_EXPIRED"
    assert cursor_expired["error"]["details"]["recoverableResources"] == ["conversations", "attachments", "device-requests"]


def test_account_uses_the_dedicated_audit_store_module(tmp_path):
    account = create_gateway_core(storage_root=tmp_path).open_gateway_account("acct_audit")

    assert isinstance(account.audit, AuditStore)


def _registry_copy(tmp_path, mutate):
    source = contract_root()
    target = tmp_path / "gateway-contract"
    shutil.copytree(source, target)
    registry_path = target / "core-dispatched-schemas.json"
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    mutate(registry)
    registry_path.write_text(json.dumps(registry, ensure_ascii=False, indent=2), encoding="utf-8")
    return target


@pytest.mark.parametrize(
    "name,mutate",
    [
        ("unknown top-level field", lambda value: value.update({"unexpected": True})),
        ("extra binding", lambda value: value["bindings"].append(dict(value["bindings"][0]))),
        ("missing catalog entry", lambda value: value["catalogEntries"].pop()),
        ("reordered catalog entries", lambda value: value["catalogEntries"].reverse()),
        ("unknown nested field", lambda value: value["catalogEntries"][0].update({"unexpected": True})),
        (
            "duplicate logical key",
            lambda value: value["catalogEntries"][1].update({"key": dict(value["catalogEntries"][0]["key"])}),
        ),
        (
            "digest mismatch",
            lambda value: value["catalogEntries"][0]["key"].update({"schemaSha256": "sha256:" + "f" * 64}),
        ),
    ],
)
def test_dispatched_registry_rejects_malformed_copied_assets(tmp_path, name, mutate):
    registry_root = _registry_copy(tmp_path, mutate)

    with pytest.raises(GatewayError) as error:
        ContractRegistry(registry_root)

    assert error.value.code == "DISPATCHED_REGISTRY_INVALID"


def test_dispatched_registry_only_accepts_the_fixed_binding_set(tmp_path):
    registry = ContractRegistry()
    value = {
        "correlationId": "correlation_1",
        "occurredAt": "2026-08-27T00:00:00.000Z",
        "payload": {"noticeCode": "maintenance"},
    }

    assert registry.validate_dispatched(
        "gateway-core-schemas-v1", {"kind": "event", "eventType": "gateway.notice"}, value
    ) is True
    assert registry.validate_dispatched(
        "untrusted-extra", {"kind": "event", "eventType": "gateway.notice"}, value
    ) is False
    assert registry.validate_dispatched(
        "gateway-core-schemas-v1",
        {"kind": "event", "eventType": "gateway.notice", "schemaSha256": "sha256:" + "a" * 64},
        value,
    ) is False


def _negotiate_body(core, schema_hash=None):
    schema_hash = schema_hash or core_schema_hash()
    return {
        "negotiationId": "neg_pre_auth",
        "protocol": {"major": 2, "minor": 1},
        "client": {"installationId": "install_pre", "appVersion": "2.0.0", "platform": "android", "platformApi": 35},
        "features": {
            "auth": ["password", "refresh"], "messages": ["chat-v1"],
            "attachments": ["staged-sha256-v1"], "events": ["sse-cursor-v1"],
            "deviceRequests": ["risk-queue-v1"],
        },
        "schemaHashes": {"core": schema_hash},
    }


def test_pre_auth_negotiate_does_not_require_account_context_and_rejects_unknown_core_hash(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    valid = core.handle({
        "requestId": "req_pre_auth", "correlationId": "cor_pre_auth",
        "method": "POST", "target": "/open-android-intelligence/v2/negotiate",
        "body": _negotiate_body(core),
    })
    invalid = core.handle({
        "requestId": "req_pre_auth_bad", "correlationId": "cor_pre_auth_bad",
        "method": "POST", "target": "/open-android-intelligence/v2/negotiate",
        "body": _negotiate_body(core, "sha256:" + "f" * 64),
    })

    assert valid["data"]["protocol"] == {"major": 2, "minor": 1}
    assert invalid["error"]["code"] == "PROTOCOL_INCOMPATIBLE"


def test_authenticated_request_with_unbound_negotiation_fails_closed(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    negotiation = core.handle({
        "requestId": "req_pre_auth", "correlationId": "cor_pre_auth",
        "method": "POST", "target": "/open-android-intelligence/v2/negotiate",
        "body": _negotiate_body(core),
    })
    assert negotiation["data"]
    unbound = core.handle({
        "context": {**_context(requestId="req_unbound"), "negotiationId": "neg_pre_auth", "installationId": "install_pre"},
        "method": "POST", "target": "/open-android-intelligence/v2/conversations",
        "idempotencyKey": "req_unbound",
        "body": {"clientConversationId": "conv_unbound"},
    })

    assert unbound["error"]["code"] == "PROTOCOL_INCOMPATIBLE"
    core.bind_negotiation("neg_pre_auth", "acct_alice", "install_pre")
    bound = core.handle({
        "context": {**_context(requestId="req_bound"), "negotiationId": "neg_pre_auth", "installationId": "install_pre"},
        "method": "POST", "target": "/open-android-intelligence/v2/conversations",
        "idempotencyKey": "req_bound",
        "body": {"clientConversationId": "conv_bound"},
    })
    assert bound["data"]["conversation"]["clientConversationId"] == "conv_bound"
    with pytest.raises(GatewayError, match="PROTOCOL_INCOMPATIBLE"):
        core.bind_negotiation("neg_pre_auth", "acct_bob", "install_pre")


def test_device_request_event_get_and_list_preserve_full_contract_metadata(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_alice")
    request = enqueue_fixture(account,
        request_id="device_req_metadata", device_id="dev_1", pairing_generation=4,
        grant_revision=7, risk="read",
        capability={"id": "org.openandroidintelligence.sms.query", "version": "1.0.0"},
        provider={"pluginId": "org.openandroidintelligence.sms", "authorKeyId": "sha256:" + "a" * 64},
        parameters={"query": "from:alice", "senders": ["alice"]},
        requires_foreground_confirmation=True,
        correlation_id="cor_metadata", now="2026-08-27T00:00:00.000Z",
    )
    event = account.events.read_after(None, "2026-08-27T00:00:01.000Z")[0]
    listed = account.device_requests.list()

    assert request["capability"] == {"id": "org.openandroidintelligence.sms.query", "version": "1.0.0"}
    assert request["provider"]["pluginId"] == "org.openandroidintelligence.sms"
    assert request["parameters"]["senders"] == ["alice"]
    assert request["createdAt"] == "2026-08-27T00:00:00.000Z"
    assert request["requiresForegroundConfirmation"] is True
    assert event["eventType"] == "device.requested"
    assert event["payload"]["parameters"] == request["parameters"]
    assert event["payload"]["expiresAt"] == request["expiresAt"]
    assert listed[0] == request


def test_device_enqueue_rejects_parameters_without_the_trusted_dispatched_binding(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_alice")

    with pytest.raises(GatewayError, match="SCHEMA_INVALID"):
        enqueue_fixture(account,
            request_id="device_req_untrusted", device_id="dev_1", pairing_generation=1,
            grant_revision=1, risk="read",
            capability={"id": "org.openandroidintelligence.sms.query", "version": "1.0.0"},
            provider={"pluginId": "org.openandroidintelligence.sms", "authorKeyId": "sha256:" + "a" * 64},
            parameters={"unexpected": True}, correlation_id="cor_untrusted",
        )


def test_device_enqueue_rolls_back_row_event_and_audit_when_event_persistence_fails(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_alice")
    account.store.database.execute(
        """
        CREATE TRIGGER fail_device_event
        BEFORE INSERT ON events
        WHEN NEW.event_type = 'device.requested'
        BEGIN SELECT RAISE(ABORT, 'device event forced failure'); END;
        """
    )

    with pytest.raises(sqlite3.Error, match="device event forced failure"):
        enqueue_fixture(account, **_device_input("device_req_atomic"))

    assert account.store.database.execute(
        "SELECT COUNT(*) FROM device_requests WHERE request_id = 'device_req_atomic'"
    ).fetchone()[0] == 0
    assert account.store.database.execute(
        "SELECT COUNT(*) FROM events WHERE event_type = 'device.requested'"
    ).fetchone()[0] == 0
    assert "device_req_atomic" not in str(account.audit.list())


def test_expired_claimed_result_commits_outcome_unknown_before_returning_error(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_alice")
    enqueue_fixture(account, **_device_input("device_req_claimed_expiry", "write", "2026-08-27T00:00:00.000Z"))
    claim = account.device_requests.claim(
        request_id="device_req_claimed_expiry", device_id="dev_1", pairing_generation=4,
        grant_revision=7, correlation_id="cor_claimed_expiry", now="2026-08-27T00:01:00.000Z",
    )

    with pytest.raises(GatewayError, match="OUTCOME_UNKNOWN"):
        account.device_requests.submit_result(
            request_id="device_req_claimed_expiry", device_id="dev_1", pairing_generation=4,
            grant_revision=7, claim_id=claim["claimId"], result={"outcome": "succeeded"},
            correlation_id="cor_late_result", now="2026-08-27T00:16:00.000Z",
        )

    assert account.device_requests.get("device_req_claimed_expiry")["state"] == "outcome_unknown"
    account.close()
    reopened = core.open_gateway_account("acct_alice")
    assert reopened.device_requests.get("device_req_claimed_expiry")["state"] == "outcome_unknown"


def test_expired_cancel_requested_result_commits_outcome_unknown_before_returning_error(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_alice")
    enqueue_fixture(account, **_device_input("device_req_cancel_expiry", "write", "2026-08-27T01:00:00.000Z"))
    claim = account.device_requests.claim(
        request_id="device_req_cancel_expiry", device_id="dev_1", pairing_generation=4,
        grant_revision=7, correlation_id="cor_cancel_claim", now="2026-08-27T01:01:00.000Z",
    )
    account.device_requests.cancel(
        request_id="device_req_cancel_expiry", device_id="dev_1", pairing_generation=4,
        grant_revision=7, correlation_id="cor_cancel", now="2026-08-27T01:02:00.000Z",
    )

    with pytest.raises(GatewayError, match="OUTCOME_UNKNOWN"):
        account.device_requests.submit_result(
            request_id="device_req_cancel_expiry", device_id="dev_1", pairing_generation=4,
            grant_revision=7, claim_id=claim["claimId"], result={"outcome": "cancelled"},
            correlation_id="cor_cancel_late_result", now="2026-08-27T01:16:00.000Z",
        )

    assert account.device_requests.get("device_req_cancel_expiry")["state"] == "outcome_unknown"


def test_expired_claimed_cancel_commits_outcome_unknown_before_returning_error(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_alice")
    enqueue_fixture(account, **_device_input("device_req_cancel_late", "write", "2026-08-27T02:00:00.000Z"))
    account.device_requests.claim(
        request_id="device_req_cancel_late", device_id="dev_1", pairing_generation=4,
        grant_revision=7, correlation_id="cor_cancel_late_claim", now="2026-08-27T02:01:00.000Z",
    )

    with pytest.raises(GatewayError, match="OUTCOME_UNKNOWN"):
        account.device_requests.cancel(
            request_id="device_req_cancel_late", device_id="dev_1", pairing_generation=4,
            grant_revision=7, correlation_id="cor_cancel_late", now="2026-08-27T02:16:00.000Z",
        )

    assert account.device_requests.get("device_req_cancel_late")["state"] == "outcome_unknown"


def test_commit_failure_does_not_corrupt_transaction_depth_or_connection(tmp_path):
    def fail_commit_once():
        fail_commit_once.calls += 1
        if fail_commit_once.calls == 1:
            raise sqlite3.OperationalError("commit forced failure")

    fail_commit_once.calls = 0
    core = create_gateway_core(storage_root=tmp_path, commit_hook=fail_commit_once)
    account = core.open_gateway_account("acct_commit_fault")

    with pytest.raises(GatewayError, match="OUTCOME_UNKNOWN"):
        with account.store.transaction():
            account.store.database.execute("INSERT INTO account_metadata(key, value) VALUES ('commit_probe', 'value')")

    assert account.store._transaction_depth == 0
    with account.store.transaction():
        assert account.store.database.execute(
            "SELECT value FROM account_metadata WHERE key = 'commit_probe'"
        ).fetchone() is None


def test_commit_unknown_marks_idempotent_request_and_blocks_duplicate_side_effect(tmp_path):
    def fail_commit_once():
        fail_commit_once.calls += 1
        if fail_commit_once.calls == 1:
            raise sqlite3.OperationalError("commit forced failure")

    fail_commit_once.calls = 0
    core = create_gateway_core(storage_root=tmp_path, commit_hook=fail_commit_once)
    request = {
        "context": _context(requestId="req_commit_unknown", correlationId="cor_commit_unknown"),
        "method": "POST", "target": "/open-android-intelligence/v2/conversations",
        "idempotencyKey": "req_commit_unknown",
        "body": {"clientConversationId": "conv_commit_unknown"},
    }

    first = core.handle(request)
    second = core.handle(request)

    assert first["error"]["code"] == "OUTCOME_UNKNOWN"
    assert second["error"]["code"] == "OUTCOME_UNKNOWN"
    account = core.open_gateway_account("acct_alice")
    assert account.store.database.execute(
        "SELECT COUNT(*) FROM uncertain_outcomes WHERE device_id = 'dev_1' AND request_id = 'req_commit_unknown'"
    ).fetchone()[0] == 1
    assert account.store.database.execute(
        "SELECT COUNT(*) FROM conversations WHERE client_conversation_id = 'conv_commit_unknown'"
    ).fetchone()[0] <= 1


def test_ledger_persistence_failure_returns_unknown_marker_instead_of_internal_error(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_alice")
    account.store.database.execute(
        """
        CREATE TRIGGER fail_ledger_persistence
        BEFORE INSERT ON idempotency_ledger
        BEGIN SELECT RAISE(ABORT, 'ledger forced failure'); END;
        """
    )
    account.close()
    request = {
        "context": _context(requestId="req_ledger_unknown", correlationId="cor_ledger_unknown"),
        "method": "POST", "target": "/open-android-intelligence/v2/conversations",
        "idempotencyKey": "req_ledger_unknown",
        "body": {"clientConversationId": "conv_ledger_unknown"},
    }

    first = core.handle(request)
    second = core.handle(request)

    assert first["error"]["code"] == "OUTCOME_UNKNOWN"
    assert second["error"]["code"] == "OUTCOME_UNKNOWN"
    account = core.open_gateway_account("acct_alice")
    assert account.store.database.execute(
        "SELECT COUNT(*) FROM uncertain_outcomes WHERE device_id = 'dev_1' AND request_id = 'req_ledger_unknown'"
    ).fetchone()[0] == 1
    assert account.store.database.execute(
        "SELECT COUNT(*) FROM conversations WHERE client_conversation_id = 'conv_ledger_unknown'"
    ).fetchone()[0] == 0
