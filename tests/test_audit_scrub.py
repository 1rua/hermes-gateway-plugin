"""Independent I-14 regression tests for Hermes audit redaction."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from open_android_intelligence_gateway.audit import scrub
from open_android_intelligence_gateway.backup import GatewayBackupService
from open_android_intelligence_gateway.core import create_gateway_core


SENSITIVE_VALUES = (
    "private-key-sentinel",
    "private_key-sentinel",
    "access-key-sentinel",
    "access_key-sentinel",
    "proof-sentinel",
    "signature-sentinel",
    "refresh-credential-sentinel",
    "refresh_credential-sentinel",
    "authorization-sentinel",
    "message-sentinel",
    "attachment-sentinel",
)


def _assert_no_sensitive_values(value: object) -> None:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True)
    for sentinel in SENSITIVE_VALUES:
        assert sentinel not in encoded


def test_scrub_recursively_denies_sensitive_field_name_variants() -> None:
    payload = {
        "actor": {
            "actorId": "actor-1",
            "privateKey": "private-key-sentinel",
            "private_key": "private_key-sentinel",
            "PRIVATE_KEY": "private-key-sentinel",
            "nested": [
                {
                    "accessKey": "access-key-sentinel",
                    "access_key": "access_key-sentinel",
                    "ACCESS_KEY": "access-key-sentinel",
                    "safe": "kept",
                }
            ],
        },
        "action": "device.request.result",
        "result": {
            "status": "accepted",
            "proof": "proof-sentinel",
            "Proof": "proof-sentinel",
            "signature": "signature-sentinel",
            "SIGNATURE": "signature-sentinel",
            "refreshCredential": "refresh-credential-sentinel",
            "refresh_credential": "refresh_credential-sentinel",
            "authorization": "authorization-sentinel",
            "Authorization": "authorization-sentinel",
            "safe": "metadata-only",
            "nested": {"message": "message-sentinel", "attachment": "attachment-sentinel"},
        },
    }

    scrubbed = scrub(payload)

    assert scrubbed == {
        "actor": {
            "actorId": "actor-1",
            "nested": [{"safe": "kept"}],
        },
        "action": "device.request.result",
        "result": {"status": "accepted", "safe": "metadata-only", "nested": {}},
    }
    _assert_no_sensitive_values(scrubbed)


def test_scrub_keeps_context_metadata_and_denies_compound_body_names() -> None:
    scrubbed = scrub({
        "contextId": "context-1",
        "context": {"requestId": "request-1"},
        "messageText": "message-text-sentinel",
        "textBody": "text-body-sentinel",
        "bodyBytes": "body-bytes-sentinel",
        "attachmentId": "attachment-1",
        "messageId": "message-1",
    })

    assert scrubbed == {
        "contextId": "context-1",
        "context": {"requestId": "request-1"},
        "attachmentId": "attachment-1",
        "messageId": "message-1",
    }


def test_scrub_denies_sensitive_fields_inside_json_serializable_tuples() -> None:
    scrubbed = scrub({
        "safe": ("kept", {"signature": "signature-sentinel", "ok": True}),
    })

    assert scrubbed == {"safe": ("kept", {"ok": True})}
    _assert_no_sensitive_values(scrubbed)


def test_audit_list_and_backup_audit_are_metadata_only(tmp_path: Path) -> None:
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_audit_scrub")

    with account.store.transaction():
        account.audit.append(
            "conversation.message.accepted",
            {
                "actorId": "actor-1",
                "authorization": "authorization-sentinel",
                "nested": {"role": "agent", "private_key": "private_key-sentinel"},
            },
            {
                "action": "conversation.message.accepted",
                "result": {
                    "status": "accepted",
                    "safeCode": "metadata-only",
                    "proof": "proof-sentinel",
                    "signature": "signature-sentinel",
                    "refreshCredential": "refresh-credential-sentinel",
                },
                "message": "message-sentinel",
                "attachment": {"content": "attachment-sentinel"},
                "access_key": "access_key-sentinel",
            },
            "correlation-audit",
            "2026-08-28T00:00:00.000Z",
        )

    listed = account.audit.list()

    assert listed == [
        {
            "eventType": "conversation.message.accepted",
            "actor": {"actorId": "actor-1", "nested": {"role": "agent"}},
            "subject": {
                "action": "conversation.message.accepted",
                "result": {"status": "accepted", "safeCode": "metadata-only"},
            },
            "correlationId": "correlation-audit",
            "occurredAt": "2026-08-28T00:00:00.000Z",
        }
    ]
    _assert_no_sensitive_values(listed)
    account.close()

    backup = GatewayBackupService(storage_root=tmp_path).export_portable("acct_audit_scrub")

    assert backup["audit"] == listed
    _assert_no_sensitive_values(backup["audit"])


def test_audit_list_defensively_scrubs_legacy_rows(tmp_path: Path) -> None:
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_audit_legacy")

    with account.store.transaction():
        account.store.database.execute(
            "INSERT INTO audit_events(event_type, actor_json, subject_json, correlation_id, occurred_at) VALUES (?, ?, ?, ?, ?)",
            (
                "legacy.action",
                json.dumps(
                    {"actorId": "actor-legacy", "private_key": "private_key-sentinel"},
                    separators=(",", ":"),
                ),
                json.dumps(
                    {
                        "action": "legacy.action",
                        "result": {"status": "accepted", "proof": "proof-sentinel"},
                        "authorization": "authorization-sentinel",
                    },
                    separators=(",", ":"),
                ),
                "correlation-legacy",
                "2026-08-28T00:00:00.000Z",
            ),
        )

    listed = account.audit.list()

    assert listed == [
        {
            "eventType": "legacy.action",
            "actor": {"actorId": "actor-legacy"},
            "subject": {"action": "legacy.action", "result": {"status": "accepted"}},
            "correlationId": "correlation-legacy",
            "occurredAt": "2026-08-28T00:00:00.000Z",
        }
    ]
    _assert_no_sensitive_values(listed)
    account.close()

    backup = GatewayBackupService(storage_root=tmp_path).export_portable("acct_audit_legacy")

    assert backup["audit"] == listed
    _assert_no_sensitive_values(backup["audit"])
