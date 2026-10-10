"""签名 HTTP 批次通过宿主消息入口得到回复，并由 SSE 返回手机。"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import secrets
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from aiohttp import ClientSession

from open_android_intelligence_gateway.adapter import BasePlatformAdapter, OpenAndroidPlatformAdapter
from open_android_intelligence_gateway.admin import create_admin_service
from open_android_intelligence_gateway.plugin import GatewayServices
from open_android_intelligence_gateway.platform_identity import GATEWAY_PLATFORM_ID
from test_conversation_rename import ACCOUNT_ID, HOST_API, _gateway
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


PREFIX = "/open-android-intelligence/v2"
NATIVE_HOST = BasePlatformAdapter.__module__ == "gateway.platforms.base"
BATCH = {
    "clientBatchId": "cb_http",
    "joinMode": "newline-v1",
    "members": [
        {"clientMessageId": "cm_http_first", "text": "  第一条\n"},
        {"clientMessageId": "cm_http_second", "text": "🙂 第二条  "},
    ],
}


def _b64url(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _signed_request(bundle, key, method, target, body=None, request_id="req_http"):
    content = b"" if body is None else json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()
    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
    nonce = _b64url(secrets.token_bytes(16))
    # 独立按契约的十个字段组装预像，不调用被测服务端的签名实现。
    preimage = "\n".join((
        "OPEN-ANDROID-INTELLIGENCE-REQUEST-V2", method, target, ACCOUNT_ID,
        bundle["deviceId"], bundle["sessionId"], request_id, timestamp,
        nonce, hashlib.sha256(content).hexdigest(),
    )).encode("ascii")
    headers = {
        "Authorization": f"Bearer {bundle['accessToken']}",
        "X-Open-Android-Intelligence-Protocol": "2.1",
        "X-Open-Android-Intelligence-Account": ACCOUNT_ID,
        "X-Open-Android-Intelligence-Device": bundle["deviceId"],
        "X-Open-Android-Intelligence-Session": bundle["sessionId"],
        "X-Open-Android-Intelligence-Request-Id": request_id,
        "X-Open-Android-Intelligence-Timestamp": timestamp,
        "X-Open-Android-Intelligence-Nonce": nonce,
        "X-Open-Android-Intelligence-Signature": _b64url(key.sign(preimage)),
    }
    if method != "GET":
        headers["Idempotency-Key"] = request_id
    if body is not None:
        headers["Content-Type"] = "application/json"
    return content, headers


def _adapter(core, exposure):
    if os.environ.get("OAI_REQUIRE_NATIVE_HERMES") == "1":
        assert NATIVE_HOST, "本次验证必须加载 Hermes 原生 BasePlatformAdapter"
    if NATIVE_HOST:
        from gateway.config import PlatformConfig
        from gateway.platform_registry import PlatformEntry, platform_registry

        platform_registry.register(PlatformEntry(
            name=GATEWAY_PLATFORM_ID, label="隔离测试 Gateway",
            adapter_factory=OpenAndroidPlatformAdapter, check_fn=lambda: True,
        ))
        config = PlatformConfig(extra={"host": "127.0.0.1", "account_id": ACCOUNT_ID})
    else:
        config = SimpleNamespace(extra={"host": "127.0.0.1", "account_id": ACCOUNT_ID})
    admin = create_admin_service(core=core, host_version="1.0.0", host_api=HOST_API)
    adapter = OpenAndroidPlatformAdapter(config, GatewayServices(core, admin, exposure))
    adapter._port = 0
    return adapter


async def _request(client, base_url, bundle, key, method, target, body=None, request_id="req_http"):
    content, headers = _signed_request(bundle, key, method, target, body, request_id)
    async with client.request(method, base_url + target, data=content if body is not None else None, headers=headers) as response:
        result = await response.json()
        assert response.status == 200, result
        return result


async def _next_event(response):
    async with asyncio.timeout(5):
        while True:
            frame = (await response.content.readuntil(b"\n\n")).decode()
            if "data: " in frame:
                event_type = next(line.removeprefix("event: ") for line in frame.splitlines() if line.startswith("event: "))
                return {**json.loads(frame.split("data: ", 1)[1]), "event": event_type}


@pytest.mark.parametrize("resource", ["message-batches", "messages"])
def test_signed_turn_replies_over_sse_and_replay_never_runs_twice(tmp_path, caplog, resource):
    async def scenario():
        key = Ed25519PrivateKey.generate()
        core, bundle, conversation_id, exposure = _gateway(tmp_path, key)
        adapter = _adapter(core, exposure)
        captured = []
        entered = asyncio.Event()
        release = asyncio.Event()

        async def agent(event):
            captured.append(event)
            entered.set()
            await release.wait()
            if NATIVE_HOST:
                return "隔离 Agent 回复"
            # 无宿主的 CI 仍覆盖插件投递、异步完成和事件回传三个真实入口。
            sent = await adapter.send(event.source.chat_id, "隔离 Agent 回复")
            assert sent.success
            await adapter.on_processing_complete(event, "success")

        adapter.set_message_handler(agent)
        assert await adapter.connect()
        base_url = f"http://127.0.0.1:{adapter._site._server.sockets[0].getsockname()[1]}"
        target = f"{PREFIX}/conversations/{conversation_id}/{resource}"
        body = BATCH if resource == "message-batches" else {"clientMessageId": "cm_http_regular", "text": "普通消息", "attachments": []}
        expected_client_ids = ["cm_http_first", "cm_http_second"] if resource == "message-batches" else ["cm_http_regular"]
        expected_text = "  第一条\n\n🙂 第二条  " if resource == "message-batches" else "普通消息"
        try:
            async with ClientSession() as client:
                _, stream_headers = _signed_request(bundle, key, "GET", f"{PREFIX}/events", request_id="req_stream")
                stream_headers["Accept"] = "text/event-stream"
                async with client.get(base_url + f"{PREFIX}/events", headers=stream_headers) as stream:
                    assert stream.status == 200
                    receipt = await _request(client, base_url, bundle, key, "POST", target, body)
                    accepted = receipt["data"] if resource == "message-batches" else receipt["data"]["message"]
                    members = accepted["members"] if resource == "message-batches" else [
                        {"messageId": accepted["messageId"], "clientMessageId": body["clientMessageId"]},
                    ]
                    assert accepted["status"] == "accepted"
                    assert [m["clientMessageId"] for m in members] == expected_client_ids
                    assert len({m["messageId"] for m in members}) == len(expected_client_ids)
                    await asyncio.wait_for(entered.wait(), 5)
                    assert captured[0].text == expected_text
                    assert captured[0].source.chat_id == conversation_id
                    assert captured[0].source.user_id == ACCOUNT_ID
                    replay = await _request(client, base_url, bundle, key, "POST", target, body)
                    assert replay == receipt
                    release.set()
                    seen = []
                    while len([event for event in seen if event.get("event") == "conversation.message.status" and event["payload"]["status"] == "completed"]) < len(members):
                        seen.append(await _next_event(stream))
                    replies = [event for event in seen if event.get("event") == "conversation.message.completed"]
                    assert len(replies) == 1
                    assert replies[0]["payload"]["conversationId"] == conversation_id
                    assert replies[0]["payload"]["text"] == "隔离 Agent 回复"
                    for member in members:
                        states = [event["payload"] for event in seen if event.get("event") == "conversation.message.status" and event["payload"]["clientMessageId"] == member["clientMessageId"]]
                        assert [state["status"] for state in states] == ["queued", "delivered", "completed"]
                        assert [state["revision"] for state in states] == [0, 1, 2]
                    finished_replay = await _request(client, base_url, bundle, key, "POST", target, body)
                    assert finished_replay == receipt
                    assert len(captured) == 1
                    assert not any("hook failed" in record.message or "Inbound dispatch failed" in record.message for record in caplog.records)
        finally:
            release.set()
            await adapter.disconnect()
            if NATIVE_HOST:
                from gateway.platform_registry import platform_registry
                platform_registry.unregister(GATEWAY_PLATFORM_ID)

    asyncio.run(scenario())


def test_completion_hook_can_be_awaited_and_publishes_terminal_status(tmp_path):
    key = Ed25519PrivateKey.generate()
    core, _, conversation_id, exposure = _gateway(tmp_path, key)
    adapter = _adapter(core, exposure)
    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        accepted = account.conversations.accept_message(
            conversation_id, "cm_hook", "完成回调", [], "dev_hook", "req_hook", "cor_hook",
        )
        dispatch = account.conversations.claim_dispatch("cm_hook")
    finally:
        account.close()
    event = SimpleNamespace(
        source=SimpleNamespace(user_id=ACCOUNT_ID), message_id="cm_hook",
        _gateway_claim_token=dispatch["claimToken"],
    )

    async def scenario():
        await adapter.on_processing_complete(event, "success")

    try:
        asyncio.run(scenario())
        account = core.open_gateway_account(ACCOUNT_ID)
        try:
            states = [event["payload"] for event in account.events.read_after(None) if event["eventType"] == "conversation.message.status"]
            assert [state["status"] for state in states] == ["queued", "delivered", "completed"]
            assert {state["messageId"] for state in states} == {accepted["messageId"]}
        finally:
            account.close()
    finally:
        if NATIVE_HOST:
            from gateway.platform_registry import platform_registry
            platform_registry.unregister(GATEWAY_PLATFORM_ID)
