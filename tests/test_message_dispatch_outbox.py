"""Durable agent handoff state uses the shared SSE status contract."""
from __future__ import annotations

import asyncio
import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from open_android_intelligence_gateway.adapter import MessageType, OpenAndroidPlatformAdapter
from open_android_intelligence_gateway.admin import create_admin_service
from open_android_intelligence_gateway.core import GatewayError, create_gateway_core
from open_android_intelligence_gateway.plugin import GatewayServices
from test_support import make_secret_store, trust_core


class _Config:
    extra = {"host": "127.0.0.1", "port": 0, "account_id": "acct_dispatch_recovery"}


def test_message_dispatch_outbox_recovery_emits_terminal_failure(tmp_path):
    core = trust_core(create_gateway_core(
        storage_root=tmp_path,
        secret_store=make_secret_store(),
    ))
    account = core.open_gateway_account("acct_dispatch_recovery")
    conversation = account.conversations.create(
        "client_conv_dispatch", None, "cor_dispatch_create",
    )
    accepted = account.conversations.accept_message(
        conversation["conversationId"], "client_msg_dispatch", "检查图片", [],
        "dev_dispatch", "req_dispatch", "cor_dispatch_message",
    )
    orphan_spool = account.paths.attachments / ".interrupted-upload.upload"
    orphan_spool.write_bytes(b"encrypted-partial-spool")
    assert core.list_gateway_account_ids() == ["acct_dispatch_recovery"]
    account.close()

    admin = create_admin_service(core=core, host_version="1.0.0", host_api={
        "minVersion": "1.0.0", "maxVersion": "1.0.0",
        "verifiedCommit": "0123456789abcdef0123456789abcdef01234567",
    })
    adapter = OpenAndroidPlatformAdapter(_Config(), GatewayServices(core, admin, None))
    asyncio.run(adapter._recover_message_dispatches("acct_dispatch_recovery"))
    assert not orphan_spool.exists()

    account = core.open_gateway_account("acct_dispatch_recovery")
    try:
        dispatch = account.conversations.dispatch_message("client_msg_dispatch")
        assert dispatch is not None
        assert dispatch["messageId"] == accepted["messageId"]
        assert dispatch["status"] == "failed"
        assert dispatch["revision"] == 1
        events = [
            event for event in account.events.read_after(None)
            if event["eventType"] == "conversation.message.status"
            and event["payload"]["clientMessageId"] == "client_msg_dispatch"
        ]
        assert [event["payload"]["status"] for event in events] == ["queued", "failed"]
        assert [event["payload"]["errorCode"] for event in events] == [None, "AGENT_UNAVAILABLE"]
    finally:
        account.close()


def test_new_conversation_command_does_not_create_agent_outbox_entry(tmp_path):
    core = trust_core(create_gateway_core(
        storage_root=tmp_path,
        secret_store=make_secret_store(),
    ))
    account = core.open_gateway_account("acct_new_command")
    source = account.conversations.create("client_conv_old", None, "cor_new_create")
    result = core._handle_new_conversation(
        account,
        source_conversation_id=source["conversationId"],
        client_message_id="client_msg_new",
        correlation_id="cor_new_command",
        device_id="dev_new_command",
        request_id="req_new_command",
    )
    try:
        dispatch = account.store.database.execute(
            "SELECT status FROM conversation_message_dispatch WHERE message_id = ?",
            (result["message"]["messageId"],),
        ).fetchone()
        assert dispatch is None
        status_events = [
            event for event in account.events.read_after(None)
            if event["eventType"] == "conversation.message.status"
        ]
        assert status_events == []
    finally:
        account.close()


def test_unknown_mime_attachment_is_a_document_media_event(tmp_path):
    core = trust_core(create_gateway_core(
        storage_root=tmp_path,
        secret_store=make_secret_store(),
    ))
    account = core.open_gateway_account("acct_unknown_media")
    content = b"custom document bytes"
    attachment = account.attachments.create(
        clientAttachmentId="client_att_custom",
        filename="payload.custom",
        mediaType="application/x-custom",
        sizeBytes=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
        correlationId="cor_custom_attachment",
    )
    account.attachments.upload_content(attachment["attachmentId"], content)
    account.attachments.commit(attachment["attachmentId"])
    conversation = account.conversations.create(
        "client_conv_custom", None, "cor_custom_conversation",
    )
    account.conversations.accept_message(
        conversation["conversationId"], "client_msg_custom", "", [attachment["attachmentId"]],
        "dev_custom", "req_custom", "cor_custom_message",
    )
    account.close()

    admin = create_admin_service(core=core, host_version="1.0.0", host_api={
        "minVersion": "1.0.0", "maxVersion": "1.0.0",
        "verifiedCommit": "0123456789abcdef0123456789abcdef01234567",
    })
    adapter = OpenAndroidPlatformAdapter(_Config(), GatewayServices(core, admin, None))
    captured = []

    async def capture(event):
        captured.append(event)

    adapter.set_message_handler(capture)
    asyncio.run(adapter._notify_agent_inbound(
        f"/open-android-intelligence/v2/conversations/{conversation['conversationId']}/messages",
        b'{"clientMessageId":"client_msg_custom","text":""}', {}, "acct_unknown_media",
    ))

    assert len(captured) == 1
    event = captured[0]
    assert event.message_type == getattr(MessageType, "DOCUMENT")
    assert event.media_types == ["application/x-custom"]
    assert len(event.media_urls) == 1
    media_path = Path(event.media_urls[0])
    assert media_path.read_bytes() == content
    asyncio.run(adapter.on_processing_complete(event, "success"))
    assert not media_path.exists()


def test_concurrent_idempotent_inbound_replay_claims_message_once(tmp_path):
    core = trust_core(create_gateway_core(
        storage_root=tmp_path,
        secret_store=make_secret_store(),
    ))
    account = core.open_gateway_account("acct_dispatch_race")
    conversation = account.conversations.create(
        "client_conv_race", None, "cor_race_conversation",
    )
    accepted = account.conversations.accept_message(
        conversation["conversationId"], "client_msg_race", "一次投递", [],
        "dev_race", "req_race", "cor_race_message",
    )
    account.close()

    admin = create_admin_service(core=core, host_version="1.0.0", host_api={
        "minVersion": "1.0.0", "maxVersion": "1.0.0",
        "verifiedCommit": "0123456789abcdef0123456789abcdef01234567",
    })
    adapter = OpenAndroidPlatformAdapter(_Config(), GatewayServices(core, admin, None))
    captured = []
    accepted_by_host = asyncio.Event()
    finish_processing = asyncio.Event()

    async def slow_host_handler(event):
        captured.append(event)
        accepted_by_host.set()
        await finish_processing.wait()

    adapter.set_message_handler(slow_host_handler)
    path = f"/open-android-intelligence/v2/conversations/{conversation['conversationId']}/messages"
    body = b'{"clientMessageId":"client_msg_race","text":"ignored raw text"}'

    async def scenario():
        first = asyncio.create_task(adapter._notify_agent_inbound(path, body, {}, "acct_dispatch_race"))
        await asyncio.wait_for(accepted_by_host.wait(), timeout=5)
        second = asyncio.create_task(adapter._notify_agent_inbound(path, body, {}, "acct_dispatch_race"))
        await asyncio.sleep(0.05)
        assert len(captured) == 1
        finish_processing.set()
        await asyncio.gather(first, second)

    asyncio.run(scenario())
    assert len(captured) == 1
    account = core.open_gateway_account("acct_dispatch_race")
    try:
        dispatch = account.conversations.dispatch_message("client_msg_race")
        assert dispatch is not None
        assert dispatch["status"] == "delivered"
        assert dispatch["claimUntil"] is None
        events = [
            event for event in account.events.read_after(None)
            if event["eventType"] == "conversation.message.status"
            and event["payload"]["clientMessageId"] == "client_msg_race"
        ]
        assert [event["payload"]["status"] for event in events] == ["queued", "delivered"]
    finally:
        account.close()
    asyncio.run(adapter.on_processing_complete(captured[0], "success"))


def test_expired_dispatch_lease_cannot_be_completed_by_a_stale_owner(tmp_path):
    core = trust_core(create_gateway_core(
        storage_root=tmp_path,
        secret_store=make_secret_store(),
    ))
    account = core.open_gateway_account("acct_dispatch_lease")
    conversation = account.conversations.create(
        "client_conv_lease", None, "cor_lease_conversation",
    )
    accepted = account.conversations.accept_message(
        conversation["conversationId"], "client_msg_lease", "重试租约", [],
        "dev_lease", "req_lease", "cor_lease_message",
    )
    first_claim = account.conversations.claim_dispatch("client_msg_lease")
    assert first_claim is not None
    account.store.database.execute(
        "UPDATE conversation_message_dispatch SET claim_until = ? WHERE message_id = ?",
        ("2020-01-01T00:00:00.000Z", accepted["messageId"]),
    )
    second_claim = account.conversations.claim_dispatch("client_msg_lease")
    assert second_claim is None
    assert account.conversations.workflow.for_message(accepted['messageId'])['state']=='unknown'
    with pytest.raises(GatewayError, match="INVALID_STATE_TRANSITION"):
        account.conversations.update_dispatch_status(
            accepted["messageId"], "delivered", None, "cor_stale_delivery",
            claim_token=first_claim["claimToken"],
        )
    account.close()

    admin = create_admin_service(core=core, host_version="1.0.0", host_api={
        "minVersion": "1.0.0", "maxVersion": "1.0.0",
        "verifiedCommit": "0123456789abcdef0123456789abcdef01234567",
    })
    adapter = OpenAndroidPlatformAdapter(_Config(), GatewayServices(core, admin, None))
    asyncio.run(adapter._recover_message_dispatches("acct_dispatch_lease"))
    account = core.open_gateway_account("acct_dispatch_lease")
    try:
        dispatch = account.conversations.dispatch_message("client_msg_lease")
        assert dispatch is not None
        assert dispatch["status"] == "failed"
        assert dispatch["claimUntil"] is None
        events = [
            event for event in account.events.read_after(None)
            if event["eventType"] == "conversation.message.status"
            and event["payload"]["clientMessageId"] == "client_msg_lease"
        ]
        assert [event["payload"]["status"] for event in events] == ["queued", "failed"]
        assert events[-1]["payload"]["errorCode"] == "AGENT_UNAVAILABLE"
    finally:
        account.close()
