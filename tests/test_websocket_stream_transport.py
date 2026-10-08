"""End-to-end event stream over WebSocket transport for Open Android Intelligence.

Exercises WebSocket handshake authentication, backlog replay, account isolation,
real-time broadcasting, progressive edits, ping/pong heartbeats, cursor recovery,
and connection cleanup on normal/abrupt disconnects.
"""

import asyncio
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

aiohttp = pytest.importorskip("aiohttp")
from aiohttp import WSServerHandshakeError, WSMsgType

from open_android_intelligence_gateway.adapter import (  # noqa: E402
    EVENT_STREAM_PATH,
    EVENT_STREAM_WS_PATH,
    OpenAndroidPlatformAdapter,
)
from open_android_intelligence_gateway.admin import (  # noqa: E402
    HostApiCompatibility,
    create_admin_service,
)
from open_android_intelligence_gateway.core import create_gateway_core  # noqa: E402
from open_android_intelligence_gateway.http import create_gateway_exposure  # noqa: E402
from open_android_intelligence_gateway.plugin import GatewayServices  # noqa: E402
from test_support import make_secret_store, make_verified_request, trust_core  # noqa: E402


TEST_HOST_API = HostApiCompatibility(
    "1.0.0", "1.0.0", "0123456789abcdef0123456789abcdef01234567"
)
ACCOUNT_ID = "acct_alice"

_real_create_gateway_core = create_gateway_core


def create_gateway_core(storage_root=None, **options):
    options.setdefault("secret_store", make_secret_store())
    return trust_core(_real_create_gateway_core(storage_root=storage_root, **options))


class _Config:
    def __init__(self, port):
        self.extra = {"port": port, "host": "127.0.0.1", "account_id": ACCOUNT_ID}


def _services(tmp_path, verify_request):
    core = create_gateway_core(storage_root=tmp_path)
    from test_support import seed_event_session
    seed_event_session(core)
    exposure = create_gateway_exposure(
        "host-route",
        core=core,
        host_version="1.0.0",
        host_api=TEST_HOST_API,
        verify_request=verify_request,
    )
    admin = create_admin_service(core=core, host_version="1.0.0", host_api=TEST_HOST_API)
    return GatewayServices(core, admin, exposure), core


def _make_verifier(account_id=ACCOUNT_ID, device_id="dev_1", now=None):
    def verifier(req):
        target = req.get("target") or req.get("url")
        return make_verified_request({
            "context": {
                "accountId": account_id,
                "deviceId": device_id,
                "sessionId": "sess_1",
                "requestId": "req_stream",
                "correlationId": "cor_stream",
                "pairingGeneration": 1,
                "grantRevision": 1,
            },
            "method": "GET",
            "target": target,
            "now": now,
        })

    return verifier


def _port(adapter):
    return adapter._site._server.sockets[0].getsockname()[1]


async def _read_json_event(ws, timeout=5.0):
    """Reads the next event from WebSocket, skipping ping/pong text frames."""
    while True:
        msg = await asyncio.wait_for(ws.receive(), timeout=timeout)
        if msg.type == WSMsgType.TEXT:
            if msg.data.strip() in ("ping", "pong"):
                continue
            data = json.loads(msg.data)
            if isinstance(data, dict) and "event" in data:
                return data
        elif msg.type in (WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.CLOSING):
            raise ConnectionResetError("WebSocket closed by remote")


def test_ws_stream_replays_backlog_is_account_scoped_and_broadcasts_realtime(tmp_path):
    async def scenario():
        services, core = _services(tmp_path, None)
        account = core.open_gateway_account(ACCOUNT_ID)
        try:
            backlog = account.events.append(
                "gateway.notice",
                "cor_backlog",
                {"noticeCode": "maintenance"},
                "2026-09-13T00:00:00.000Z",
            )
        finally:
            account.close()

        exposure = create_gateway_exposure(
            "host-route",
            core=core,
            host_version="1.0.0",
            host_api=TEST_HOST_API,
            verify_request=_make_verifier(now="2026-09-13T00:00:00.000Z"),
        )
        services = GatewayServices(core, services.admin, exposure)
        adapter = OpenAndroidPlatformAdapter(_Config(0), services)
        assert await adapter.connect() is True
        try:
            async with aiohttp.ClientSession() as session:
                url = f"http://127.0.0.1:{_port(adapter)}{EVENT_STREAM_PATH}"
                async with session.ws_connect(url) as ws:
                    replayed = await _read_json_event(ws)
                    assert replayed["id"] == backlog["eventId"]
                    assert replayed["event"] == "gateway.notice"
                    replayed_data = json.loads(replayed["data"])
                    assert replayed_data["payload"] == {"noticeCode": "maintenance"}

                    # An event delivered for another account must not leak to this stream
                    adapter._enqueue_frame("acct_other", b"id: evt_leak\nevent: gateway.notice\ndata: {}\n\n")

                    # Real-time event for this account
                    await adapter.complete_message("conv_1", "msg_1", "hello phone")
                    delivered = await _read_json_event(ws)
                    assert delivered["id"] != "evt_leak"
                    assert delivered["event"] == "conversation.message.completed"
                    delivered_data = json.loads(delivered["data"])
                    assert delivered_data["payload"]["messageId"] == "msg_1"
                    assert delivered_data["payload"]["text"] == "hello phone"
        finally:
            await adapter.disconnect()

    asyncio.run(scenario())


def test_ws_stream_on_ws_path(tmp_path):
    async def scenario():
        services, core = _services(tmp_path, None)
        account = core.open_gateway_account(ACCOUNT_ID)
        try:
            backlog = account.events.append(
                "gateway.notice",
                "cor_backlog_ws",
                {"noticeCode": "ws_route_active"},
                "2026-09-13T00:00:00.000Z",
            )
        finally:
            account.close()

        exposure = create_gateway_exposure(
            "host-route",
            core=core,
            host_version="1.0.0",
            host_api=TEST_HOST_API,
            verify_request=_make_verifier(now="2026-09-13T00:00:00.000Z"),
        )
        services = GatewayServices(core, services.admin, exposure)
        adapter = OpenAndroidPlatformAdapter(_Config(0), services)
        assert await adapter.connect() is True
        try:
            async with aiohttp.ClientSession() as session:
                url = f"http://127.0.0.1:{_port(adapter)}{EVENT_STREAM_WS_PATH}"
                async with session.ws_connect(url) as ws:
                    replayed = await _read_json_event(ws)
                    assert replayed["id"] == backlog["eventId"]
                    assert replayed["event"] == "gateway.notice"
                    replayed_data = json.loads(replayed["data"])
                    assert replayed_data["payload"] == {"noticeCode": "ws_route_active"}

                    await adapter.complete_message("conv_ws", "msg_ws", "websocket works")
                    delivered = await _read_json_event(ws)
                    assert delivered["event"] == "conversation.message.completed"
                    delivered_data = json.loads(delivered["data"])
                    assert delivered_data["payload"]["text"] == "websocket works"
        finally:
            await adapter.disconnect()

    asyncio.run(scenario())


def test_ws_stream_without_verifier_answers_401(tmp_path):
    async def scenario():
        services, _core = _services(tmp_path, None)
        adapter = OpenAndroidPlatformAdapter(_Config(0), services)
        assert await adapter.connect() is True
        try:
            async with aiohttp.ClientSession() as session:
                # Test on EVENT_STREAM_PATH
                with pytest.raises(WSServerHandshakeError) as exc_info:
                    await session.ws_connect(f"http://127.0.0.1:{_port(adapter)}{EVENT_STREAM_PATH}")
                assert exc_info.value.status == 401

                # Test on EVENT_STREAM_WS_PATH
                with pytest.raises(WSServerHandshakeError) as exc_info_ws:
                    await session.ws_connect(f"http://127.0.0.1:{_port(adapter)}{EVENT_STREAM_WS_PATH}")
                assert exc_info_ws.value.status == 401
        finally:
            await adapter.disconnect()

    asyncio.run(scenario())


def test_ws_stream_progressive_delivery(tmp_path):
    async def scenario():
        services, core = _services(tmp_path, None)
        exposure = create_gateway_exposure(
            "host-route",
            core=core,
            host_version="1.0.0",
            host_api=TEST_HOST_API,
            verify_request=_make_verifier(now="2026-09-13T00:00:00.000Z"),
        )
        services = GatewayServices(core, services.admin, exposure)
        adapter = OpenAndroidPlatformAdapter(_Config(0), services)
        assert await adapter.connect() is True
        try:
            async with aiohttp.ClientSession() as session:
                url = f"http://127.0.0.1:{_port(adapter)}{EVENT_STREAM_WS_PATH}"
                async with session.ws_connect(url) as ws:
                    # 1. Send with expect_edits -> stream_delta
                    res = await adapter.send("conv_ws", "Hello", metadata={"expect_edits": True})
                    assert res.success is True
                    msg_id = res.message_id
                    frame1 = await _read_json_event(ws)
                    assert frame1["event"] == "conversation.message.delta"
                    assert json.loads(frame1["data"])["payload"]["text"] == "Hello"

                    # 2. edit_message intermediate -> stream_delta
                    ok_edit = await adapter.edit_message("conv_ws", msg_id, "Hello world", finalize=False)
                    assert ok_edit is True
                    frame2 = await _read_json_event(ws)
                    assert frame2["event"] == "conversation.message.delta"
                    assert json.loads(frame2["data"])["payload"]["text"] == "Hello world"

                    # 3. edit_message finalize -> complete_message
                    ok_final = await adapter.edit_message("conv_ws", msg_id, "Hello world!", finalize=True)
                    assert ok_final is True
                    frame3 = await _read_json_event(ws)
                    assert frame3["event"] == "conversation.message.completed"
                    assert json.loads(frame3["data"])["payload"]["text"] == "Hello world!"
        finally:
            await adapter.disconnect()

    asyncio.run(scenario())


def test_ws_stream_heartbeat_and_ping_pong(tmp_path):
    async def scenario():
        services, core = _services(tmp_path, None)
        exposure = create_gateway_exposure(
            "host-route",
            core=core,
            host_version="1.0.0",
            host_api=TEST_HOST_API,
            verify_request=_make_verifier(now="2026-09-13T00:00:00.000Z"),
        )
        services = GatewayServices(core, services.admin, exposure)
        adapter = OpenAndroidPlatformAdapter(_Config(0), services)
        assert await adapter.connect() is True
        try:
            async with aiohttp.ClientSession() as session:
                url = f"http://127.0.0.1:{_port(adapter)}{EVENT_STREAM_WS_PATH}"
                async with session.ws_connect(url) as ws:
                    # Application-level text ping / pong
                    await ws.send_str("ping")
                    resp = await asyncio.wait_for(ws.receive_str(), timeout=5.0)
                    assert resp == "pong"

                    # Protocol-level ping
                    await ws.ping()
                    await asyncio.sleep(0.05)
                    assert not ws.closed

                    # Ensure event delivery continues normally after ping/pong
                    await adapter.complete_message("conv_hb", "msg_hb", "after ping")
                    delivered = await _read_json_event(ws)
                    assert delivered["event"] == "conversation.message.completed"
                    assert json.loads(delivered["data"])["payload"]["text"] == "after ping"
        finally:
            await adapter.disconnect()

    asyncio.run(scenario())


def test_ws_stream_cleanup_on_normal_close(tmp_path):
    async def scenario():
        services, core = _services(tmp_path, None)
        exposure = create_gateway_exposure(
            "host-route",
            core=core,
            host_version="1.0.0",
            host_api=TEST_HOST_API,
            verify_request=_make_verifier(now="2026-09-13T00:00:00.000Z"),
        )
        services = GatewayServices(core, services.admin, exposure)
        adapter = OpenAndroidPlatformAdapter(_Config(0), services)
        assert await adapter.connect() is True
        try:
            async with aiohttp.ClientSession() as session:
                url = f"http://127.0.0.1:{_port(adapter)}{EVENT_STREAM_WS_PATH}"
                ws = await session.ws_connect(url)
                # Verify queue is active
                assert ACCOUNT_ID in adapter._active_sse_queues
                assert len(adapter._active_sse_queues[ACCOUNT_ID]) == 1

                # Normal close
                await ws.close()
                await asyncio.sleep(0.05)

                # Verify queue cleaned up
                assert ACCOUNT_ID not in adapter._active_sse_queues
        finally:
            await adapter.disconnect()

    asyncio.run(scenario())


def test_ws_stream_cleanup_on_abrupt_disconnect(tmp_path):
    async def scenario():
        services, core = _services(tmp_path, None)
        exposure = create_gateway_exposure(
            "host-route",
            core=core,
            host_version="1.0.0",
            host_api=TEST_HOST_API,
            verify_request=_make_verifier(now="2026-09-13T00:00:00.000Z"),
        )
        services = GatewayServices(core, services.admin, exposure)
        adapter = OpenAndroidPlatformAdapter(_Config(0), services)
        assert await adapter.connect() is True
        try:
            session = aiohttp.ClientSession()
            url = f"http://127.0.0.1:{_port(adapter)}{EVENT_STREAM_WS_PATH}"
            ws = await session.ws_connect(url)
            assert ACCOUNT_ID in adapter._active_sse_queues
            assert len(adapter._active_sse_queues[ACCOUNT_ID]) == 1

            # Abruptly close session (terminates underlying TCP transport without WS close frame)
            await session.close()
            await asyncio.sleep(0.1)

            # Verify queue cleaned up
            assert ACCOUNT_ID not in adapter._active_sse_queues
        finally:
            await adapter.disconnect()

    asyncio.run(scenario())


def test_ws_stream_resumes_from_cursor(tmp_path):
    async def scenario():
        services, core = _services(tmp_path, None)
        account = core.open_gateway_account(ACCOUNT_ID)
        try:
            evt1 = account.events.append(
                "gateway.notice", "cor_1", {"noticeCode": "step-1"}, "2026-09-13T00:00:00.000Z",
            )
            evt2 = account.events.append(
                "gateway.notice", "cor_2", {"noticeCode": "step-2"}, "2026-09-13T00:00:01.000Z",
            )
        finally:
            account.close()

        exposure = create_gateway_exposure(
            "host-route",
            core=core,
            host_version="1.0.0",
            host_api=TEST_HOST_API,
            verify_request=_make_verifier(now="2026-09-13T00:00:02.000Z"),
        )
        services = GatewayServices(core, services.admin, exposure)
        adapter = OpenAndroidPlatformAdapter(_Config(0), services)
        assert await adapter.connect() is True
        try:
            async with aiohttp.ClientSession() as session:
                # Connect with cursor pointing to evt1
                url = f"http://127.0.0.1:{_port(adapter)}{EVENT_STREAM_WS_PATH}?cursor={evt1['eventId']}"
                async with session.ws_connect(url) as ws:
                    replayed = await _read_json_event(ws)
                    # Only evt2 should be received
                    assert replayed["id"] == evt2["eventId"]
                    replayed_data = json.loads(replayed["data"])
                    assert replayed_data["payload"] == {"noticeCode": "step-2"}

                    # No more backlog events immediately pending
                    await adapter.complete_message("conv_c", "msg_c", "resumed")
                    delivered = await _read_json_event(ws)
                    assert delivered["id"] != evt1["eventId"]
                    assert delivered["id"] != evt2["eventId"]
                    assert delivered["event"] == "conversation.message.completed"
        finally:
            await adapter.disconnect()

    asyncio.run(scenario())
