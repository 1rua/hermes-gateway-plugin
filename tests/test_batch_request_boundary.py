"""通过完整 Core 请求入口验证批次受理与共享请求时间。"""
from __future__ import annotations

from datetime import datetime, timezone

from open_android_intelligence_gateway.core import create_gateway_core
from test_support import make_secret_store, make_verified_request


ACCOUNT_ID = "acct_batch_boundary"
PREFIX = "/open-android-intelligence/v2"
NOW = datetime(2026, 10, 10, 0, 0, tzinfo=timezone.utc)
BATCH = {
    "clientBatchId": "cb_boundary",
    "joinMode": "newline-v1",
    "members": [
        {"clientMessageId": "cm_first", "text": "第一条"},
        {"clientMessageId": "cm_second", "text": "第二条"},
    ],
}


def _core_and_conversation(tmp_path):
    core = create_gateway_core(tmp_path, secret_store=make_secret_store())
    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        conversation = account.conversations.create("cc_boundary", "原始标题", "cor_create", NOW)
    finally:
        account.close()
    return core, conversation["conversationId"]


def _request(method, target, body=None, request_id="req_boundary"):
    return make_verified_request({
        "context": {
            "accountId": ACCOUNT_ID,
            "deviceId": "dev_boundary",
            "sessionId": "sess_boundary",
            "pairingGeneration": 1,
            "grantRevision": 1,
            "requestId": request_id,
            "correlationId": request_id,
        },
        "method": method,
        "target": target,
        "body": body,
        "idempotencyKey": request_id if method != "GET" else None,
        "now": NOW,
    })


def test_batch_handle_accepts_every_member_and_preserves_idempotent_receipt(tmp_path):
    core, conversation_id = _core_and_conversation(tmp_path)
    target = f"{PREFIX}/conversations/{conversation_id}/message-batches"

    response = core.handle(_request("POST", target, BATCH))

    assert "data" in response, response
    receipt = response["data"]
    assert receipt["status"] == "accepted"
    assert [member["clientMessageId"] for member in receipt["members"]] == ["cm_first", "cm_second"]
    assert len({member["messageId"] for member in receipt["members"]}) == 2
    assert core.handle(_request("POST", target, BATCH)) == response
    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        dispatch = account.conversations.claim_dispatch("cm_first", now=NOW)
        assert dispatch["text"] == "第一条\n第二条"
        assert account.conversations.claim_dispatch("cm_second", now=NOW) is None
    finally:
        account.close()


def test_cancel_handle_returns_native_receipt_and_replays_once(tmp_path):
    core, conversation_id = _core_and_conversation(tmp_path)
    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        with account.store.transaction():
            receipt = account.conversations.workflow.accept_batch(
                conversation_id, BATCH, {
                    "deviceId": "dev_boundary", "requestId": "req_seed", "correlationId": "cor_seed",
                }, NOW,
            )
        account.conversations.claim_dispatch("cm_first", now=NOW)
    finally:
        account.close()
    calls = []

    def cancel(account_id, cid, generation_id):
        calls.append((account_id, cid, generation_id))
        return "CANCELLED"

    core.generation_canceller = cancel
    generation_id = receipt["generationId"]
    target = f"{PREFIX}/conversations/{conversation_id}/generations/{generation_id}/cancel"
    request = _request("POST", target, {"requestId": "req_cancel"}, "req_cancel")

    response = core.handle(request)

    assert response.get("data") == {"outcome": "CANCELLED", "generationId": generation_id}, response
    assert core.handle(request) == response
    assert calls == [(ACCOUNT_ID, conversation_id, generation_id)]
    current = core.handle(_request("GET", f"{PREFIX}/conversations/{conversation_id}/generations/current"))
    assert current["data"]["generation"] is None


def test_snapshot_handle_uses_request_time_without_entering_rename_branch(tmp_path):
    core, conversation_id = _core_and_conversation(tmp_path)

    response = core.handle(_request("GET", f"{PREFIX}/sync/snapshot"))

    assert "data" in response, response
    data = response["data"]
    assert [row["conversationId"] for row in data["conversations"]] == [conversation_id]
    assert data["pendingDeviceRequests"] == []
    events = core.handle(_request("GET", f"{PREFIX}/events"))["data"]["events"]
    baseline = next(event for event in events if event["eventId"] == data["baselineCursor"])
    assert baseline["eventType"] == "gateway.notice"
    assert baseline["occurredAt"] == "2026-10-10T00:00:00.000Z"
