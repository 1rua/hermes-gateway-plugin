"""独立子进程运行 Android 互通夹具，检查启动、HTTP 入口与安全结束。"""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from aiohttp import ClientSession
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from test_batch_http_dispatch import BATCH, PREFIX, _b64url, _next_event, _request, _signed_request
from test_support import contract_root, core_schema_hash


@contextmanager
def _fixture_process(tmp_path, echo_agent):
    log_path = tmp_path / "fixture-stderr.txt"
    env = dict(os.environ)
    env.pop("OAI_GATEWAY_MASTER_KEY_FILE", None)
    env["HERMES_HOME"] = str(tmp_path / "inherited-hermes-home")
    env["HERMES_TEST_ISOLATION"] = env["HERMES_HOME"]
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    fixture = Path(__file__).with_name("android_gateway_fixture.py")
    command = [sys.executable, str(fixture), "--contract-root", str(contract_root())]
    if echo_agent:
        command.append("--echo-agent")
        # 此路径不存在；若 echo 误用继承的线上密钥路径，启动必须失败。
        for name in ("OAI_GATEWAY_MASTER_KEY_FILE", "OPEN_ANDROID_INTELLIGENCE_GATEWAY_MASTER_KEY_FILE", "OPEN_ANDROID_GATEWAY_MASTER_KEY_FILE"):
            env[name] = str(tmp_path / "inherited-master-key")
        env["OPEN_ANDROID_GATEWAY_PORT"] = "11451"
        env["OPEN_ANDROID_GATEWAY_HOST"] = "203.0.113.10"
        env["OPEN_ANDROID_ACCOUNT_ID"] = "inherited-account"
    with log_path.open("w") as stderr:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=stderr, text=True, env=env)
        try:
            yield process, log_path
        finally:
            process.terminate()
            process.wait(timeout=10)
            process.stdout.close()


async def _fixture_url(process, log_path):
    first_line = await asyncio.wait_for(asyncio.to_thread(process.stdout.readline), timeout=10)
    assert first_line.startswith("http://127.0.0.1:"), log_path.read_text()
    parsed = urlsplit(first_line.strip())
    assert parsed.hostname == "127.0.0.1" and parsed.port > 0
    return first_line.strip()


@pytest.mark.parametrize("echo_agent", [False, True])
def test_fixture_cli_starts_on_random_loopback_port_and_stops(tmp_path, echo_agent):
    async def scenario():
        with _fixture_process(tmp_path, echo_agent) as (process, log_path):
            base_url = await _fixture_url(process, log_path)
            async with ClientSession() as client:
                async with client.get(base_url + "/fixture-not-a-gateway-route") as response:
                    assert response.status == 404
        assert process.poll() is not None
        if echo_agent:
            assert not (tmp_path / "inherited-master-key").exists()
            assert not (tmp_path / "inherited-hermes-home").exists()

    asyncio.run(scenario())


async def _login(client, base_url, key):
    negotiation_id = "neg_fixture_cli"
    installation_id = "install_fixture_cli"
    hello = {
        "negotiationId": negotiation_id,
        "protocol": {"major": 2, "minor": 1},
        "client": {"installationId": installation_id, "appVersion": "fixture-test", "platform": "android", "platformApi": 35},
        "features": {
            "auth": ["password"], "messages": ["chat-v1"], "attachments": ["staged-sha256-v1"],
            "events": ["sse-cursor-v1"], "deviceRequests": ["risk-queue-v1"],
            "conversationUi": ["message-batches-v1", "newline-v1"],
        },
        "schemaHashes": {"core": core_schema_hash()},
    }
    async with client.post(base_url + PREFIX + "/negotiate", json=hello) as response:
        negotiated = await response.json()
        assert response.status == 200, negotiated
        assert "message-batches-v1" in negotiated["data"]["features"]["conversationUi"]
    login = {
        "negotiationId": negotiation_id, "username": "alice", "password": "android-fixture-only",
        "installation": {"installationId": installation_id, "displayName": "隔离夹具设备", "devicePublicKey": _b64url(key.public_key().public_bytes_raw())},
    }
    async with client.post(base_url + PREFIX + "/sessions/password", json=login) as response:
        result = await response.json()
        assert response.status == 200
        assert result["data"]["accountId"] == "alice"
        return result["data"]


@pytest.mark.parametrize("echo_agent", [False, True])
def test_fixture_cli_password_login_batch_and_reply_semantics(tmp_path, echo_agent):
    async def scenario():
        with _fixture_process(tmp_path, echo_agent) as (process, log_path):
            base_url = await _fixture_url(process, log_path)
            key = Ed25519PrivateKey.generate()
            async with ClientSession() as client:
                bundle = await _login(client, base_url, key)
                created = await _request(client, base_url, bundle, key, "POST", PREFIX + "/conversations", {"clientConversationId": "cc_fixture_cli"}, "req_cli_create")
                conversation_id = created["data"]["conversation"]["conversationId"]
                _, headers = _signed_request(bundle, key, "GET", PREFIX + "/events", request_id="req_cli_stream")
                headers["Accept"] = "text/event-stream"
                async with client.get(base_url + PREFIX + "/events", headers=headers) as stream:
                    assert stream.status == 200
                    if echo_agent:
                        await _request(client, base_url, bundle, key, "GET", PREFIX + "/sync/snapshot", request_id="req_cli_snapshot")
                        while True:
                            event = await _next_event(stream)
                            if event["event"] == "gateway.notice" and event["payload"]["noticeCode"] == "SYNC_BASELINE":
                                break
                    else:
                        assert await stream.read() == b": fixture connected\n\n"
                    target = f"{PREFIX}/conversations/{conversation_id}/message-batches"
                    receipt = await _request(client, base_url, bundle, key, "POST", target, BATCH, "req_cli_batch")
                    members = receipt["data"]["members"]
                    assert len({member["messageId"] for member in members}) == 2
                    if echo_agent:
                        seen = []
                        while sum(event["event"] == "conversation.message.status" and event["payload"]["status"] == "completed" for event in seen) < 2:
                            seen.append(await _next_event(stream))
                        replies = [event for event in seen if event["event"] == "conversation.message.completed"]
                        assert len(replies) == 1
                        assert replies[0]["payload"]["conversationId"] == conversation_id
                        assert replies[0]["payload"]["text"] == "fixture-agent-reply:\n  第一条\n\n🙂 第二条  "
                    replay = await _request(client, base_url, bundle, key, "POST", target, BATCH, "req_cli_batch")
                    assert replay == receipt
                    if echo_agent:
                        ordinary = {"clientMessageId": "cm_cli_regular", "text": "后续普通消息", "attachments": []}
                        await _request(client, base_url, bundle, key, "POST", f"{PREFIX}/conversations/{conversation_id}/messages", ordinary, "req_cli_regular")
                        while True:
                            event = await _next_event(stream)
                            if event["event"] == "conversation.message.completed":
                                assert event["payload"]["text"] == "fixture-agent-reply:\n后续普通消息"
                                break
        diagnostic_rows = [json.loads(line) for line in log_path.read_text().splitlines() if line.startswith("{")]
        if echo_agent:
            turns = [row for row in diagnostic_rows if row.get("fixtureEvent") == "agent-turn"]
            assert [row["clientMessageId"] for row in turns] == ["cm_http_first", "cm_cli_regular"]
            assert "hook failed" not in log_path.read_text()
            assert "Inbound dispatch failed" not in log_path.read_text()
            mode = next(row for row in diagnostic_rows if row.get("fixtureMode") == "echo-agent")
            if os.environ.get("OAI_REQUIRE_NATIVE_HERMES") == "1":
                assert mode["host"] == "native"
        else:
            assert not any(row.get("fixtureEvent") == "agent-turn" for row in diagnostic_rows)

    asyncio.run(scenario())
