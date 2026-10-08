from test_support import enqueue_fixture
import hashlib
import json
import sqlite3
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from open_android_intelligence_gateway.core import GatewayError, create_gateway_core
from open_android_intelligence_gateway.http import create_gateway_exposure
from test_support import core_schema_hash, make_secret_store, make_verified_request, trust_core


_real_create_gateway_core = create_gateway_core


def create_gateway_core(storage_root=None, **options):
    options.setdefault("secret_store", make_secret_store())
    return trust_core(_real_create_gateway_core(storage_root=storage_root, **options))


NEGOTIATION_BODY = {
    "negotiationId": "neg_attachment_policy",
    "protocol": {"major": 2, "minor": 1},
    "client": {
        "installationId": "install_attachment_policy",
        "appVersion": "2.0.0",
        "platform": "android",
        "platformApi": 35,
    },
    "features": {
        "auth": ["password", "refresh"],
        "messages": ["chat-v1"],
        "attachments": ["staged-sha256-v1"],
        "events": ["sse-cursor-v1"],
        "deviceRequests": ["risk-queue-v1"],
    },
    "schemaHashes": {"core": core_schema_hash()},
}


def _negotiate(core):
    response = core.handle(
        {
            "requestId": "req_attachment_negotiate",
            "correlationId": "cor_attachment_negotiate",
            "method": "POST",
            "target": "/open-android-intelligence/v2/negotiate",
            "body": NEGOTIATION_BODY,
        }
    )
    assert "data" in response
    assert response["protocol"] == "2.1"
    assert response["data"]["protocol"] == {"major": 2, "minor": 1}
    return response["data"]["limits"]


def _create_input(size_bytes=4, media_type="text/plain", client_id="att_client"):
    return {
        "clientAttachmentId": client_id,
        "filename": "note.txt",
        "mediaType": media_type,
        "sizeBytes": size_bytes,
        "sha256": hashlib.sha256(b"body").hexdigest(),
        "correlationId": f"cor_{client_id}",
    }


def _create(account, body=b"body", *, now=None, client_id="att_client", media_type="text/plain"):
    values = _create_input(len(body), media_type, client_id)
    values["sha256"] = hashlib.sha256(body).hexdigest()
    if now is not None:
        values["now"] = now
    return account.attachments.create(**values)


def _expire_row(account, attachment_id):
    account.store.database.execute(
        "UPDATE attachments SET expires_at = ?, storage_revision = storage_revision + 1 WHERE attachment_id = ?",
        ("2020-01-01T00:00:00.000Z", attachment_id),
    )


def test_success_and_failure_envelopes_use_protocol_2_1(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    context = {
        "accountId": "acct_protocol_21",
        "deviceId": "dev_protocol_21",
        "sessionId": "sess_protocol_21",
        "requestId": "req_protocol_21",
        "correlationId": "cor_protocol_21",
        "pairingGeneration": 1,
        "grantRevision": 1,
    }

    success = core.handle(make_verified_request({
        "context": context,
        "method": "GET",
        "target": "/open-android-intelligence/v2/conversations",
    }))
    failure = core.handle(make_verified_request({
        "context": {**context, "requestId": "req_protocol_21_error", "correlationId": "cor_protocol_21_error"},
        "method": "GET",
        "target": "/open-android-intelligence/v2/not-a-route",
    }))

    assert success["protocol"] == "2.1"
    assert failure["protocol"] == "2.1"
    assert "error" in failure


def test_negotiation_has_no_product_size_or_media_limits(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    limits = _negotiate(core)
    assert "maxSingleAttachmentBytes" not in limits
    assert "maxMessageAttachmentBytes" not in limits
    assert "allowedMediaTypes" not in limits


def test_attachment_metadata_accepts_media_types_without_product_allowlist(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_attachment_media")

    attachment = account.attachments.create(
        **_create_input(
            26_214_401,
            media_type="application/x-archive-custom",
            client_id="att_unbounded_metadata",
        )
    )

    assert attachment["sizeBytes"] == 26_214_401
    assert "mediaType" not in attachment
    assert account.attachments.get_record(attachment["attachmentId"])["mediaType"] == "application/x-archive-custom"

    parameterized = account.attachments.create(
        **_create_input(
            26_214_401,
            media_type="Image/PNG; charset=binary",
            client_id="att_raw_mime",
        )
    )
    assert account.attachments.get_record(parameterized["attachmentId"])["mediaType"] == "Image/PNG; charset=binary"


def test_client_attachment_create_retry_is_metadata_idempotent_and_old_duplicates_open(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_client_attachment_retry")
    body = b"retryable attachment"
    digest = hashlib.sha256(body).hexdigest()
    values = {
        "clientAttachmentId": "att_retry_same_id",
        "filename": "retry.bin",
        "mediaType": "application/octet-stream",
        "sizeBytes": len(body),
        "sha256": digest,
        "correlationId": "cor_retry_first",
    }
    first = account.attachments.create(**values)
    # Pre-2.1 storage did not enforce uniqueness, so retain a historical
    # duplicate row to ensure startup does not need a destructive index migration.
    account.store.database.execute(
        """
        INSERT INTO attachments(attachment_id, client_attachment_id, filename, media_type, size_bytes,
          sha256, state, content_path, cas_path, created_at, expires_at, delivered_at, acknowledged_at,
          owner_device_id, owner_pairing_generation)
        VALUES ('att_legacy_duplicate', ?, ?, ?, ?, ?, 'created', NULL, NULL, ?, ?, NULL, NULL,
          '__gateway_internal_unattributed__', 0)
        """,
        (
            values["clientAttachmentId"], values["filename"], "application/octet-stream",
            len(body), digest, "2026-09-20T00:00:00.000Z", "2026-09-20T01:00:00.000Z",
        ),
    )
    account.close()

    reopened = core.open_gateway_account("acct_client_attachment_retry")
    try:
        before = reopened.store.database.execute(
            "SELECT COUNT(*) FROM attachments WHERE client_attachment_id = ?",
            (values["clientAttachmentId"],),
        ).fetchone()[0]
        retry = reopened.attachments.create(
            **{**values, "correlationId": "cor_retry_new_request_id"},
        )
        after = reopened.store.database.execute(
            "SELECT COUNT(*) FROM attachments WHERE client_attachment_id = ?",
            (values["clientAttachmentId"],),
        ).fetchone()[0]
        assert retry["attachmentId"] in {first["attachmentId"], "att_legacy_duplicate"}
        assert retry["status"] == "staged"
        assert after == before == 2

        with pytest.raises(GatewayError) as conflict:
            reopened.attachments.create(
                **{**values, "filename": "other.bin", "correlationId": "cor_retry_conflict"},
            )
        assert conflict.value.code == "IDEMPOTENCY_CONFLICT"
    finally:
        reopened.close()


def test_attachment_storage_fence_rejects_legacy_unbound_inserts(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_attachment_format_fence")
    try:
        with pytest.raises(sqlite3.IntegrityError, match="ATTACHMENT_PAIRING_BINDING_REQUIRED"):
            account.store.database.execute(
                """
                INSERT INTO attachments(attachment_id, client_attachment_id, filename, media_type, size_bytes,
                  sha256, state, content_path, cas_path, created_at, expires_at, delivered_at, acknowledged_at)
                VALUES ('att_old_writer', 'old_writer', 'legacy.bin', 'application/octet-stream', 0,
                  ?, 'created', NULL, NULL, '2026-09-23T00:00:00.000Z', '2026-09-24T00:00:00.000Z', NULL, NULL)
                """,
                ("0" * 64,),
            )

        attachment = _create(account, body=b"", client_id="att_old_writer_update")
        with pytest.raises(sqlite3.IntegrityError, match="ATTACHMENT_STORAGE_VERSION_UNSUPPORTED"):
            account.store.database.execute(
                "UPDATE attachments SET state = 'uploading', content_path = ? WHERE attachment_id = ?",
                ("old-plaintext.stage", attachment["attachmentId"]),
            )
    finally:
        account.close()


def test_unknown_attachment_storage_version_fails_closed(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_attachment_unknown_format")
    account.store.database.execute(
        "UPDATE account_metadata SET value = '3' WHERE key = 'attachment_storage_format'"
    )
    account.close()

    with pytest.raises(GatewayError, match="ATTACHMENT_STORAGE_VERSION_UNSUPPORTED"):
        core.open_gateway_account("acct_attachment_unknown_format")


def test_streamed_attachment_stays_encrypted_and_opens_as_bounded_verified_chunks(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_streamed_attachment")
    body = bytes(range(251)) * 2_000
    attachment = account.attachments.create(
        clientAttachmentId="att_streamed",
        filename="photo.bin",
        mediaType="image/x-custom",
        sizeBytes=len(body),
        sha256=hashlib.sha256(body).hexdigest(),
        correlationId="cor_streamed",
    )
    attachment_id = attachment["attachmentId"]

    chunks = (body[offset:offset + 8192] for offset in range(0, len(body), 8192))
    uploaded = account.attachments.upload_content_stream(attachment_id, chunks)
    stage_path = Path(
        account.store.database.execute(
            "SELECT content_path FROM attachments WHERE attachment_id = ?",
            (attachment_id,),
        ).fetchone()[0]
    )
    verified = account.attachments.commit(attachment_id)
    opened_chunks = list(account.attachments.open_verified_stream(attachment_id))

    assert uploaded["status"] == "staged"
    assert verified["status"] == "uploaded"
    assert body not in stage_path.read_bytes()
    assert max(map(len, opened_chunks)) <= account.attachments.stream_chunk_bytes
    assert b"".join(opened_chunks) == body


def _create_verified_stream(account, client_id, body):
    attachment = account.attachments.create(
        clientAttachmentId=client_id,
        filename=f"{client_id}.png",
        mediaType="image/png",
        sizeBytes=len(body),
        sha256=hashlib.sha256(body).hexdigest(),
        correlationId=f"cor_{client_id}",
    )
    attachment_id = attachment["attachmentId"]
    account.attachments.upload_content_stream(
        attachment_id,
        (body[offset:offset + account.attachments.stream_chunk_bytes]
         for offset in range(0, len(body), account.attachments.stream_chunk_bytes)),
    )
    account.attachments.commit(attachment_id)
    row = account.store.database.execute(
        "SELECT cas_path FROM attachments WHERE attachment_id = ?", (attachment_id,),
    ).fetchone()
    return attachment_id, Path(row["cas_path"])


def test_chunk_aead_rejects_reordering_and_cross_attachment_ciphertext(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_chunk_binding")
    body = bytes(range(251)) * 1_000
    first_id, first_path = _create_verified_stream(account, "att_first", body)
    second_id, second_path = _create_verified_stream(account, "att_second", body)

    second_path.write_bytes(first_path.read_bytes())
    with pytest.raises(GatewayError) as attachment_swap:
        list(account.attachments.open_verified_stream(second_id))
    assert attachment_swap.value.code == "DECRYPTION_FAILED"

    stored = first_path.read_bytes()
    magic = b"OAI-ATTACHMENT-AEAD-STREAM\x02\n"
    assert stored.startswith(magic)
    offset = len(magic)
    frames = []
    while offset < len(stored):
        frame_start = offset
        plain_length, sealed_length = struct.unpack(">II", stored[offset:offset + 8])
        offset += 8 + sealed_length
        frames.append(stored[frame_start:offset])
        if plain_length == 0:
            break
    assert len(frames) >= 3
    frames[0], frames[1] = frames[1], frames[0]
    first_path.write_bytes(magic + b"".join(frames))
    with pytest.raises(GatewayError) as reordered:
        list(account.attachments.open_verified_stream(first_id))
    assert reordered.value.code == "DECRYPTION_FAILED"


def test_chunk_aead_rejects_ciphertext_moved_between_accounts_and_truncation(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    alice = core.open_gateway_account("acct_chunk_alice")
    bob = core.open_gateway_account("acct_chunk_bob")
    body = b"account-bound encrypted image" * 5_000
    alice_id, alice_path = _create_verified_stream(alice, "att_alice", body)
    bob_id, bob_path = _create_verified_stream(bob, "att_bob", body)

    bob_path.write_bytes(alice_path.read_bytes())
    with pytest.raises(GatewayError) as account_swap:
        list(bob.attachments.open_verified_stream(bob_id))
    assert account_swap.value.code == "DECRYPTION_FAILED"

    alice_path.write_bytes(alice_path.read_bytes()[:-1])
    with pytest.raises(GatewayError) as truncated:
        list(alice.attachments.open_verified_stream(alice_id))
    assert truncated.value.code == "DECRYPTION_FAILED"


def test_server_owns_attachment_ttl_and_rejects_caller_expiration_override(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    limits = _negotiate(core)
    account = core.open_gateway_account("acct_attachment_ttl")

    with pytest.raises(GatewayError) as error:
        account.attachments.create(
            **_create_input(client_id="att_ttl_override"),
            now="2026-08-28T00:00:00.000Z",
            expiresAt="2099-01-01T00:00:00.000Z",
        )

    assert error.value.code == "SCHEMA_INVALID"
    assert limits["attachmentTtlSeconds"] == 3600


def test_message_accepts_verified_attachments_above_previous_total_limit(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_message_attachment_unbounded")
    size = 26_214_401
    attachment_ids = []
    for index, fill in enumerate((b"a", b"b")):
        digest = hashlib.sha256()
        block = fill * 65_536
        remaining_for_digest = size
        while remaining_for_digest:
            part = block[:min(len(block), remaining_for_digest)]
            digest.update(part)
            remaining_for_digest -= len(part)
        expected_sha256 = digest.hexdigest()
        remaining = size

        def chunks():
            nonlocal remaining
            while remaining:
                chunk = block[:min(len(block), remaining)]
                remaining -= len(chunk)
                yield chunk

        attachment = account.attachments.create(
            clientAttachmentId=f"att_message_{index}",
            filename=f"large-{index}.bin",
            mediaType="application/x-test-binary",
            sizeBytes=size,
            sha256=expected_sha256,
            correlationId=f"cor_message_{index}",
        )
        account.attachments.upload_content_stream(attachment["attachmentId"], chunks())
        account.attachments.commit(attachment["attachmentId"])
        attachment_ids.append(attachment["attachmentId"])

    conversation = account.conversations.create(
        client_conversation_id="conv_message_limit",
        title=None,
        correlation_id="cor_message_limit",
    )

    accepted = account.conversations.accept_message(
        conversation_id=conversation["conversationId"],
        client_message_id="msg_message_unbounded",
        text="two individually large attachments",
        attachment_ids=attachment_ids,
        device_id="dev_1",
        request_id="req_message_unbounded",
        correlation_id="cor_message_unbounded_send",
    )

    assert accepted["status"] == "accepted"


def test_overdue_attachment_rejects_upload_and_stabilizes_expired_state(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_expired_upload")
    attachment = _create(
        account,
        now="2020-01-01T00:00:00.000Z",
        client_id="att_expired_upload",
    )

    with pytest.raises(GatewayError) as error:
        account.attachments.upload_content(attachment["attachmentId"], b"body")

    assert error.value.code == "ATTACHMENT_EXPIRED"
    assert account.attachments.get(attachment["attachmentId"])["status"] == "expired"


def test_expired_commit_cannot_verify_or_keep_staged_bytes(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_expired_commit")
    attachment = _create(account, client_id="att_expired_commit")
    account.attachments.upload_content(attachment["attachmentId"], b"body")
    _expire_row(account, attachment["attachmentId"])

    with pytest.raises(GatewayError) as error:
        account.attachments.commit(attachment["attachmentId"])

    assert error.value.code == "ATTACHMENT_EXPIRED"
    record = account.attachments.get(attachment["attachmentId"])
    assert record["status"] == "expired"
    assert set(record) == {"attachmentId", "status", "sizeBytes", "sha256"}
    assert account.attachments.get_record(attachment["attachmentId"])["hasStagedBytes"] is False


def test_get_expired_attachment_does_not_expose_uploading_state(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_expired_get")
    attachment = _create(account, client_id="att_expired_get")
    account.attachments.upload_content(attachment["attachmentId"], b"body")
    _expire_row(account, attachment["attachmentId"])

    record = account.attachments.get(attachment["attachmentId"])

    assert record["status"] == "expired"
    assert set(record) == {"attachmentId", "status", "sizeBytes", "sha256"}
    assert account.attachments.get_record(attachment["attachmentId"])["hasStagedBytes"] is False


def test_expired_attachment_cannot_be_referenced_by_a_message(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_expired_reference")
    attachment = _create(account, client_id="att_expired_reference")
    account.attachments.upload_content(attachment["attachmentId"], b"body")
    account.attachments.commit(attachment["attachmentId"])
    _expire_row(account, attachment["attachmentId"])
    conversation = account.conversations.create(
        client_conversation_id="conv_expired_reference",
        title=None,
        correlation_id="cor_expired_reference",
    )

    with pytest.raises(GatewayError) as error:
        account.conversations.accept_message(
            conversation_id=conversation["conversationId"],
            client_message_id="msg_expired_reference",
            text="must not reference expired attachment",
            attachment_ids=[attachment["attachmentId"]],
            device_id="dev_1",
            request_id="req_expired_reference",
            correlation_id="cor_expired_reference_send",
            now="2030-01-01T00:00:00.000Z",
        )

    assert error.value.code == "ATTACHMENT_EXPIRED"
    assert account.attachments.get(attachment["attachmentId"])["status"] == "expired"


def test_cleanup_expires_overdue_attachment_before_deleting_references(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_expired_cleanup")
    attachment = _create(account, client_id="att_expired_cleanup")
    account.attachments.upload_content(attachment["attachmentId"], b"body")
    _expire_row(account, attachment["attachmentId"])

    account.attachments.cleanup()

    row = account.store.database.execute(
        "SELECT state, content_path, cas_path FROM attachments WHERE attachment_id = ?",
        (attachment["attachmentId"],),
    ).fetchone()
    assert row["state"] == "deleted"
    assert row["content_path"] is None
    assert row["cas_path"] is None


def test_expiring_one_attachment_does_not_remove_a_shared_cas_reference(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_shared_cas_expiry")
    first = _create(account, client_id="att_shared_expiry_first")
    second = _create(account, client_id="att_shared_expiry_second")
    for attachment in (first, second):
        account.attachments.upload_content(attachment["attachmentId"], b"body")
        account.attachments.commit(attachment["attachmentId"])

    _expire_row(account, first["attachmentId"])
    assert account.attachments.get(first["attachmentId"])["status"] == "expired"

    second_record = account.attachments.get(second["attachmentId"])
    assert second_record["status"] == "uploaded"
    second_row = account.store.database.execute(
        "SELECT cas_path FROM attachments WHERE attachment_id = ?",
        (second["attachmentId"],),
    ).fetchone()
    assert Path(second_row["cas_path"]).is_file()


def test_attachment_storage_without_an_explicit_aead_key_fails_closed(tmp_path):
    core = _real_create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_no_aead")

    with pytest.raises(GatewayError) as error:
        account.attachments.create(**_create_input(client_id="att_no_aead"))

    assert error.value.code == "MASTER_KEY_UNAVAILABLE"
    assert account.master_key_ref == ""
    stored_ref = account.store.database.execute(
        "SELECT value FROM account_metadata WHERE key = 'master_key_ref'"
    ).fetchone()[0]
    assert stored_ref == ""
    blocked = core.handle(make_verified_request({
            "context": {
                "accountId": "acct_no_aead", "deviceId": "dev_1", "sessionId": "sess_1",
                "requestId": "req_no_aead", "correlationId": "cor_no_aead",
                "pairingGeneration": 1, "grantRevision": 1,
            },
            "method": "GET", "target": "/open-android-intelligence/v2/conversations",
        }))
    assert blocked["error"]["code"] == "MASTER_KEY_UNAVAILABLE"


class _ReferenceOnlySecretStore:
    def get_or_create(self, name):
        return f"operator-ref://{name}"


def test_reference_only_secret_store_does_not_enable_plaintext_fallback(tmp_path):
    core = _real_create_gateway_core(
        storage_root=tmp_path, secret_store=_ReferenceOnlySecretStore()
    )
    account = core.open_gateway_account("acct_reference_only")

    with pytest.raises(GatewayError) as error:
        account.attachments.create(**_create_input(client_id="att_reference_only"))

    assert error.value.code == "MASTER_KEY_UNAVAILABLE"
    assert account.master_key_ref == ""


def test_attachment_stage_and_cas_are_sealed_by_the_host_aead_provider(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_sealed_attachment")
    body = b"attachment body must not be stored in plaintext"
    attachment = _create(account, body=body, client_id="att_sealed")

    uploaded = account.attachments.upload_content(attachment["attachmentId"], body)
    stage_path = Path(
        account.store.database.execute(
            "SELECT content_path FROM attachments WHERE attachment_id = ?",
            (attachment["attachmentId"],),
        ).fetchone()[0]
    )
    stage_bytes = stage_path.read_bytes()
    assert uploaded["status"] == "staged"
    assert body not in stage_bytes
    assert stage_bytes.startswith(b"OAI-ATTACHMENT-AEAD-STREAM\x02\n")

    verified = account.attachments.commit(attachment["attachmentId"])
    cas_path = Path(
        account.store.database.execute(
            "SELECT cas_path FROM attachments WHERE attachment_id = ?",
            (attachment["attachmentId"],),
        ).fetchone()[0]
    )
    assert verified["status"] == "uploaded"
    assert body not in cas_path.read_bytes()
    assert account.attachments.get(attachment["attachmentId"])["status"] == "uploaded"


def test_device_parameters_and_event_payload_are_sealed_at_rest(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_sealed_device")
    parameters = {"query": "from:alice", "senders": ["alice"]}
    request = enqueue_fixture(account,
        **{
            "request_id": "device_req_sealed",
            "device_id": "dev_1",
            "pairing_generation": 4,
            "grant_revision": 7,
            "risk": "read",
            "capability": {"id": "org.openandroidintelligence.sms.query", "version": "1.0.0"},
            "provider": {"pluginId": "org.openandroidintelligence.sms", "authorKeyId": "sha256:" + "a" * 64},
            "parameters": parameters,
            "correlation_id": "cor_sealed_device",
        }
    )
    row = account.store.database.execute(
        "SELECT parameters_json FROM device_requests WHERE request_id = 'device_req_sealed'"
    ).fetchone()
    event_row = account.store.database.execute(
        "SELECT payload_json FROM events WHERE event_type = 'device.requested'"
    ).fetchone()

    assert request["parameters"] == parameters
    assert "from:alice" not in row["parameters_json"]
    assert "from:alice" not in event_row["payload_json"]
    assert account.device_requests.get("device_req_sealed")["parameters"] == parameters
    assert account.events.read_after(None)[0]["payload"]["parameters"] == parameters


def test_idempotency_outcome_is_sealed_at_rest_and_replays_through_the_provider(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    request = {
        "context": {
            "accountId": "acct_sealed_idempotency", "deviceId": "dev_1",
            "sessionId": "sess_1", "requestId": "req_sealed_idempotency",
            "correlationId": "cor_sealed_idempotency", "pairingGeneration": 1,
            "grantRevision": 1,
        },
        "method": "POST", "target": "/open-android-intelligence/v2/conversations",
        "idempotencyKey": "req_sealed_idempotency",
        "body": {"clientConversationId": "conv_sealed_idempotency", "title": "private title"},
    }

    first = core.handle(request)
    account = core.open_gateway_account("acct_sealed_idempotency")
    row = account.store.database.execute(
        "SELECT outcome_json FROM idempotency_ledger WHERE request_id = 'req_sealed_idempotency'"
    ).fetchone()

    assert first["data"]["conversation"]["title"] == "private title"
    assert row["outcome_json"].startswith("aead-v1:")
    assert "private title" not in row["outcome_json"]
    assert core.handle(request) == first


def test_tampered_attachment_ciphertext_fails_closed(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_tampered_attachment")
    body = b"tamper me"
    attachment = _create(account, body=body, client_id="att_tampered")
    account.attachments.upload_content(attachment["attachmentId"], body)
    stage_path = Path(
        account.store.database.execute(
            "SELECT content_path FROM attachments WHERE attachment_id = ?",
            (attachment["attachmentId"],),
        ).fetchone()[0]
    )
    stored = bytearray(stage_path.read_bytes())
    stored[-1] ^= 1
    stage_path.write_bytes(bytes(stored))

    with pytest.raises(GatewayError) as error:
        account.attachments.commit(attachment["attachmentId"])

    assert error.value.code == "DECRYPTION_FAILED"


class _RawRequest:
    def __init__(self, body, url):
        self.method = "PUT"
        self.url = url
        self.headers = {"content-type": "application/octet-stream"}
        self.rawHeaders = ("content-type", "application/octet-stream")
        self.body = body


class _RawResponse:
    def __init__(self):
        self.status_code = 0
        self.headers = {}
        self.body = ""

    def set_header(self, name, value):
        self.headers[name.lower()] = value

    def end(self, body):
        self.body = body


class _RawCore:
    def __init__(self):
        self.requests = []

    def handle(self, request):
        self.requests.append(request)
        return {
            "requestId": "request-raw-attachment",
            "correlationId": "correlation-raw-attachment",
            "protocol": "2.1",
            "data": {"accepted": True},
        }


def test_legacy_one_shot_stage_is_failed_for_reupload_on_startup(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_legacy_stage")
    body = b"legacy attachment stage"
    attachment = _create(account, body=body, client_id="att_legacy_stage")
    stage_path = account.paths.attachments / f"{attachment['attachmentId']}.stage"
    stage_path.write_text(
        account.store.seal_bytes(
            body, account.attachments._legacy_attachment_aad(attachment["sha256"]),
        ),
        encoding="ascii",
    )
    account.store.database.execute(
        "UPDATE attachments SET state = 'uploading', content_path = ?, storage_revision = storage_revision + 1 WHERE attachment_id = ?",
        (str(stage_path), attachment["attachmentId"]),
    )
    account.close()

    recovered = core.open_gateway_account("acct_legacy_stage")
    try:
        row = recovered.attachments.get_record(attachment["attachmentId"])
        assert row["state"] == "failed"
        assert row["status"] == "failed"
        assert row["hasStagedBytes"] is False
        assert recovered.attachments.open_verified_stream(attachment["attachmentId"])  # denied below
    except GatewayError as exc:
        assert exc.code == "ATTACHMENT_EXPIRED"
    else:
        raise AssertionError("A one-shot legacy stage must never be delivered")
    finally:
        recovered.close()


def test_legacy_stage_recovery_retries_after_a_startup_commit_failure(tmp_path):
    fail_once = True

    def fail_first_recovery_commit():
        nonlocal fail_once
        if fail_once:
            fail_once = False
            raise RuntimeError("simulated interruption during legacy recovery")

    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_legacy_retry")
    body = b"legacy attachment stage"
    attachment = _create(account, body=body, client_id="att_legacy_retry")
    stage_path = account.paths.attachments / f"{attachment['attachmentId']}.stage"
    stage_path.write_text(
        account.store.seal_bytes(
            body, account.attachments._legacy_attachment_aad(attachment["sha256"]),
        ),
        encoding="ascii",
    )
    account.store.database.execute(
        "UPDATE attachments SET state = 'uploading', content_path = ?, storage_revision = storage_revision + 1 WHERE attachment_id = ?",
        (str(stage_path), attachment["attachmentId"]),
    )
    database_path = account.paths.database
    account.close()

    core.commit_hook = fail_first_recovery_commit
    with pytest.raises(GatewayError, match="OUTCOME_UNKNOWN"):
        core.open_gateway_account("acct_legacy_retry")

    assert stage_path.is_file()
    with sqlite3.connect(database_path) as database:
        row = database.execute(
            "SELECT state, content_path FROM attachments WHERE attachment_id = ?",
            (attachment["attachmentId"],),
        ).fetchone()
    assert row == ("uploading", str(stage_path))

    core.commit_hook = None
    recovered = core.open_gateway_account("acct_legacy_retry")
    try:
        assert recovered.attachments.get(attachment["attachmentId"])["status"] == "failed"
    finally:
        recovered.close()
