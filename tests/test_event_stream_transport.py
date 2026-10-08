"""End-to-end event stream over the real aiohttp transport.

The handshake and framing are covered by `test_event_stream.py`; this file runs
the actual server the phone talks to, so the streaming loop, the account
isolation and the response headers are exercised rather than assumed.
"""

import asyncio
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

aiohttp = pytest.importorskip("aiohttp")

from open_android_intelligence_gateway.adapter import (  # noqa: E402
    EVENT_STREAM_PATH,
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
        "host-route", core=core, host_version="1.0.0",
        host_api=TEST_HOST_API, verify_request=verify_request,
    )
    admin = create_admin_service(core=core, host_version="1.0.0", host_api=TEST_HOST_API)
    return GatewayServices(core, admin, exposure), core


def _verifier(target, now=None):
    verified = make_verified_request({
        "context": {
            "accountId": ACCOUNT_ID, "deviceId": "dev_1", "sessionId": "sess_1",
            "requestId": "req_stream", "correlationId": "cor_stream",
            "pairingGeneration": 1, "grantRevision": 1,
        },
        "method": "GET",
        "target": target,
        "now": now,
    })
    return lambda request: verified


def _port(adapter):
    return adapter._site._server.sockets[0].getsockname()[1]


async def _read_event_frame(response, timeout=5.0):
    """Reads until a frame carrying an event id arrives, skipping heartbeat comments."""
    while True:
        raw = await asyncio.wait_for(response.content.readuntil(b"\n\n"), timeout)
        frame = raw.decode("utf-8")
        if frame.lstrip().startswith(":"):
            continue
        return frame


def _id_of(frame):
    return frame.split("\n", 1)[0].removeprefix("id: ")


def _data_of(frame):
    return json.loads(frame.split("data: ", 1)[1])


def test_stream_replays_backlog_is_account_scoped_and_has_no_wildcard_cors(tmp_path):
    async def scenario():
        services, core = _services(tmp_path, None)
        account = core.open_gateway_account(ACCOUNT_ID)
        try:
            backlog = account.events.append(
                "gateway.notice", "cor_backlog", {"noticeCode": "maintenance"},
                "2026-09-13T00:00:00.000Z",
            )
        finally:
            account.close()

        exposure = create_gateway_exposure(
            "host-route", core=core, host_version="1.0.0", host_api=TEST_HOST_API,
            verify_request=_verifier(EVENT_STREAM_PATH, now="2026-09-13T00:00:00.000Z"),
        )
        services = GatewayServices(core, services.admin, exposure)
        adapter = OpenAndroidPlatformAdapter(_Config(0), services)
        assert await adapter.connect() is True
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"http://127.0.0.1:{_port(adapter)}{EVENT_STREAM_PATH}",
                    headers={"Accept": "text/event-stream"},
                ) as response:
                    assert response.status == 200
                    assert response.headers["Content-Type"] == "text/event-stream"
                    assert "Access-Control-Allow-Origin" not in response.headers

                    replayed = await _read_event_frame(response)
                    assert _id_of(replayed) == backlog["eventId"]
                    assert "event: gateway.notice" in replayed
                    assert _data_of(replayed)["payload"] == {"noticeCode": "maintenance"}

                    # An event delivered for another account must not appear on
                    # this stream: delivery is scoped by account, not broadcast.
                    adapter._enqueue_frame("acct_other", b"id: evt_leak\nevent: gateway.notice\ndata: {}\n\n")

                    await adapter.complete_message("conv_1", "msg_1", "hello phone")
                    delivered = await _read_event_frame(response)
                    assert _id_of(delivered) != "evt_leak"
                    assert "event: conversation.message.completed" in delivered
                    payload = _data_of(delivered)["payload"]
                    assert payload["messageId"] == "msg_1"
                    assert payload["text"] == "hello phone"
        finally:
            await adapter.disconnect()

    asyncio.run(scenario())


def test_stream_without_a_verifier_answers_401_over_http(tmp_path):
    async def scenario():
        services, _core = _services(tmp_path, None)
        adapter = OpenAndroidPlatformAdapter(_Config(0), services)
        assert await adapter.connect() is True
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"http://127.0.0.1:{_port(adapter)}{EVENT_STREAM_PATH}",
                    headers={"Accept": "text/event-stream"},
                ) as response:
                    assert response.status == 401
                    body = await response.json()
                    assert body["error"]["code"] == "AUTHENTICATION_REQUIRED"
        finally:
            await adapter.disconnect()

    asyncio.run(scenario())


def test_adapter_streaming_edits_progressive_delivery(tmp_path):
    async def scenario():
        services, core = _services(tmp_path, None)
        exposure = create_gateway_exposure(
            "host-route", core=core, host_version="1.0.0", host_api=TEST_HOST_API,
            verify_request=_verifier(EVENT_STREAM_PATH, now="2026-09-13T00:00:00.000Z"),
        )
        services = GatewayServices(core, services.admin, exposure)
        adapter = OpenAndroidPlatformAdapter(_Config(0), services)
        assert adapter.REQUIRES_EDIT_FINALIZE is True
        assert await adapter.connect() is True
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"http://127.0.0.1:{_port(adapter)}{EVENT_STREAM_PATH}",
                    headers={"Accept": "text/event-stream"},
                ) as response:
                    assert response.status == 200

                    # 1. Send with expect_edits -> stream_delta
                    res = await adapter.send("conv_stream", "Hello", metadata={"expect_edits": True})
                    assert res.success is True
                    msg_id = res.message_id
                    frame1 = await _read_event_frame(response)
                    assert "event: conversation.message.delta" in frame1
                    assert _data_of(frame1)["payload"]["text"] == "Hello"

                    # 2. edit_message intermediate -> stream_delta
                    ok_edit = await adapter.edit_message("conv_stream", msg_id, "Hello world", finalize=False)
                    assert ok_edit is True
                    frame2 = await _read_event_frame(response)
                    assert "event: conversation.message.delta" in frame2
                    assert _data_of(frame2)["payload"]["text"] == "Hello world"

                    # 3. edit_message finalize -> complete_message
                    ok_final = await adapter.edit_message("conv_stream", msg_id, "Hello world!", finalize=True)
                    assert ok_final is True
                    frame3 = await _read_event_frame(response)
                    assert "event: conversation.message.completed" in frame3
                    assert _data_of(frame3)["payload"]["text"] == "Hello world!"
        finally:
            await adapter.disconnect()

    asyncio.run(scenario())


def test_conversation_patch_updates_title_and_appends_event(tmp_path):
    async def scenario():
        services, core = _services(tmp_path, None)
        account = core.open_gateway_account(ACCOUNT_ID)
        try:
            conv = account.conversations.create("cconv_1", "原标题", "cor_create")
            conv_id = conv["conversationId"]
        finally:
            account.close()

        req = make_verified_request({
            "context": {
                "accountId": ACCOUNT_ID, "deviceId": "dev_1", "sessionId": "sess_1",
                "requestId": "req_patch", "correlationId": "cor_patch",
                "pairingGeneration": 1, "grantRevision": 1,
            },
            "idempotencyKey": "req_patch",
            "method": "PATCH",
            "target": f"/open-android-intelligence/v2/conversations/{conv_id}",
            "body": {"title": "量子计算与经典物理的核心区别"},
        })
        res = core.handle(req)
        assert "data" in res
        assert res["data"]["conversation"]["title"] == "量子计算与经典物理的核心区别"

        account = core.open_gateway_account(ACCOUNT_ID)
        try:
            persisted = account.conversations.get(conv_id)
            assert persisted["title"] == "量子计算与经典物理的核心区别"
            events = account.events.read_after(None)
            title_events = [e for e in events if e["eventType"] == "conversation.title.updated"]
            assert len(title_events) == 1
            assert title_events[0]["payload"]["title"] == "量子计算与经典物理的核心区别"
            assert title_events[0]["payload"]["newTitle"] == "量子计算与经典物理的核心区别"
        finally:
            account.close()

    asyncio.run(scenario())


class _SessionStoreDouble:
    """The host session store, reduced to the one call the binding makes."""

    def __init__(self):
        self.calls: list[tuple[str, bool]] = []
        self.sessions: dict[str, str] = {}

    def get_or_create_session(self, source, force_new: bool = False):
        chat_id = str(getattr(source, "chat_id", ""))
        self.calls.append((chat_id, bool(force_new)))
        if force_new or chat_id not in self.sessions:
            self.sessions[chat_id] = f"sess_{len(self.sessions) + 1}"
        entry = type("_Entry", (), {})()
        entry.session_key = f"agent:main:open_android:dm:{chat_id}"
        entry.session_id = self.sessions[chat_id]
        return entry


def test_a_committed_core_event_reaches_the_live_stream(tmp_path):
    """Contract §9: a committed event is delivered, not merely stored.

    `/new` is answered by the Core, so its `conversation.command.result` is
    appended by a write the adapter never performs. The phone is waiting for
    exactly that frame on the connection it already holds, so delivery has to
    come from the commit itself: a frame that only appears on the next
    subscription is a command result the user never sees.
    """
    async def scenario():
        services, core = _services(tmp_path, None)
        account = core.open_gateway_account(ACCOUNT_ID)
        try:
            source = account.conversations.create("cconv_source", "来源会话", "cor_source")["conversationId"]
        finally:
            account.close()

        exposure = create_gateway_exposure(
            "host-route", core=core, host_version="1.0.0", host_api=TEST_HOST_API,
            verify_request=_verifier(EVENT_STREAM_PATH, now="2026-09-13T00:00:00.000Z"),
        )
        services = GatewayServices(core, services.admin, exposure)
        adapter = OpenAndroidPlatformAdapter(_Config(0), services)
        store = _SessionStoreDouble()
        adapter.set_session_store(store)
        assert await adapter.connect() is True
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"http://127.0.0.1:{_port(adapter)}{EVENT_STREAM_PATH}",
                    headers={"Accept": "text/event-stream"},
                ) as response:
                    assert response.status == 200

                    accepted = core.handle(make_verified_request({
                        "context": {
                            "accountId": ACCOUNT_ID, "deviceId": "dev_1", "sessionId": "sess_1",
                            "requestId": "req_new_command", "correlationId": "cor_new_command",
                            "pairingGeneration": 1, "grantRevision": 1,
                        },
                        "idempotencyKey": "req_new_command",
                        "method": "POST",
                        "target": f"/open-android-intelligence/v2/conversations/{source}/messages",
                        "body": {"clientMessageId": "msg_new_command", "text": "/new", "attachments": []},
                    }))
                    assert accepted["data"]["message"]["status"] == "accepted"

                    frame = await _read_event_frame(response)
                    assert "event: conversation.command.result" in frame
                    payload = _data_of(frame)["payload"]
                    assert payload["outcome"] == "created-conversation"
                    assert payload["sourceConversationId"] == source
                    assert payload["conversationId"] != source

                    # The same commit also gives the new conversation its own Agent
                    # session: the command entry decides that a conversation exists,
                    # the host decides which session owns it.
                    created = payload["conversationId"]
                    binding = await _await_agent_session_binding(core, created)
                    assert binding is not None
                    assert binding["createdVia"] == "new-command"
                    assert binding["agentSessionId"] == store.sessions[created]
                    assert store.calls == [(created, True)]
                    assert binding["agentSessionId"] != store.sessions.get(source)
        finally:
            await adapter.disconnect()

    asyncio.run(scenario())


def _binding(core, conversation_id: str):
    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        return account.agent_sessions.lookup(conversation_id)
    finally:
        account.close()


async def _await_agent_session_binding(core, conversation_id: str, timeout: float = 5.0):
    """Wait for the host's session id, not just for the row.

    The command entry records the row inside its own transaction; the adapter
    attaches the host's session id from a background task afterwards. Waiting for
    the row alone would let a test read the state between the two and call a
    correct binding empty.
    """
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        binding = _binding(core, conversation_id)
        if binding is not None and binding["agentSessionId"]:
            return binding
        await asyncio.sleep(0.05)
    return _binding(core, conversation_id)


def test_committed_events_for_another_account_stay_off_this_stream(tmp_path):
    """The delivery seam keeps the per-account scoping the subscription had."""
    async def scenario():
        services, core = _services(tmp_path, None)
        account = core.open_gateway_account(ACCOUNT_ID)
        try:
            account.conversations.create("cconv_alice", "Alice", "cor_alice")
        finally:
            account.close()
        other = core.open_gateway_account("acct_bob")
        try:
            other.conversations.create("cconv_bob", "Bob", "cor_bob")
        finally:
            other.close()

        exposure = create_gateway_exposure(
            "host-route", core=core, host_version="1.0.0", host_api=TEST_HOST_API,
            verify_request=_verifier(EVENT_STREAM_PATH, now="2026-09-13T00:00:00.000Z"),
        )
        services = GatewayServices(core, services.admin, exposure)
        adapter = OpenAndroidPlatformAdapter(_Config(0), services)
        assert await adapter.connect() is True
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"http://127.0.0.1:{_port(adapter)}{EVENT_STREAM_PATH}",
                    headers={"Accept": "text/event-stream"},
                ) as response:
                    assert response.status == 200

                    bob = core.open_gateway_account("acct_bob")
                    try:
                        bob.events.append("gateway.notice", "cor_bob_notice", {"noticeCode": "bob"})
                    finally:
                        bob.close()

                    alice = core.open_gateway_account(ACCOUNT_ID)
                    try:
                        alice.events.append("gateway.notice", "cor_alice_notice", {"noticeCode": "alice"})
                    finally:
                        alice.close()

                    frame = await _read_event_frame(response)
                    assert _data_of(frame)["payload"] == {"noticeCode": "alice"}
        finally:
            await adapter.disconnect()

    asyncio.run(scenario())


def test_command_catalog_includes_all_standard_commands(tmp_path):
    services, core = _services(tmp_path, None)
    res = core.command_catalog_response("zh-CN")
    commands = {c["invocation"]: c for c in res["commands"]}
    for cmd in ["/new", "/models", "/status", "/review", "/gateway", "/clear", "/help"]:
        assert cmd in commands, f"Missing command: {cmd}"
    assert commands["/models"]["acceptsArguments"] is True
    assert commands["/status"]["acceptsArguments"] is False
    assert commands["/review"]["acceptsArguments"] is True
    assert commands["/gateway"]["acceptsArguments"] is True
    assert commands["/clear"]["acceptsArguments"] is False
    assert commands["/help"]["acceptsArguments"] is True
    assert commands["/new"]["acceptsArguments"] is False
