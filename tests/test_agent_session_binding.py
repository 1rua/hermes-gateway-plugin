"""One Gateway conversation owns exactly one Agent session.

The Agent host holds the memory, so "the phone switched conversations" only means
something if the host routes that conversation to its own session. These tests
drive the adapter's own seams: the reserved `/new` command is not handed to the
Agent, a message ensures the binding before it is dispatched, and opening a
conversation binds it without forcing a new session.
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from open_android_intelligence_gateway.adapter import (  # noqa: E402
    OpenAndroidPlatformAdapter,
    _conversation_id_of,
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
ACCOUNT_ID = "acct_agent_session"
CONVERSATIONS = "/open-android-intelligence/v2/conversations"

_real_create_gateway_core = create_gateway_core


def create_gateway_core(storage_root=None, **options):
    options.setdefault("secret_store", make_secret_store())
    return trust_core(_real_create_gateway_core(storage_root=storage_root, **options))


class _Config:
    def __init__(self, account_id: str = ACCOUNT_ID):
        self.extra = {"host": "127.0.0.1", "port": 0, "account_id": account_id}


class _Entry:
    """The two fields the binding records, and nothing else."""

    def __init__(self, chat_id: str, session_id: str):
        self.session_key = f"agent:main:open_android:dm:{chat_id}"
        self.session_id = session_id


class _SessionStoreDouble:
    """The host's session store, reduced to the one call the binding makes."""

    def __init__(self):
        self._db = self
        self.calls: list[tuple[str, bool]] = []
        self.sessions: dict[str, str] = {}

    def get_messages(self, session_id, include_inactive=False):
        return []

    def get_or_create_session(self, source, force_new: bool = False):
        chat_id = str(getattr(source, "chat_id", ""))
        self.calls.append((chat_id, bool(force_new)))
        if force_new or chat_id not in self.sessions:
            self.sessions[chat_id] = f"sess_{len(self.sessions) + 1}"
        return _Entry(chat_id, self.sessions[chat_id])


def _make_core(tmp_path):
    return create_gateway_core(storage_root=tmp_path)


def _adapter(core, session_store=None, verify_request=None):
    exposure = create_gateway_exposure(
        "host-route", core=core, host_version="1.0.0", host_api=TEST_HOST_API,
        verify_request=verify_request,
    )
    admin = create_admin_service(core=core, host_version="1.0.0", host_api=TEST_HOST_API)
    adapter = OpenAndroidPlatformAdapter(_Config(), GatewayServices(core, admin, exposure))
    if session_store is not None:
        adapter.set_session_store(session_store)
    return adapter


def _seed_conversation(core, client_id: str) -> str:
    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        return account.conversations.create(client_id, "会话", f"cor_{client_id}")["conversationId"]
    finally:
        account.close()


def _binding(core, conversation_id: str):
    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        return account.agent_sessions.lookup(conversation_id)
    finally:
        account.close()


def _messages_path(conversation_id: str) -> str:
    return f"{CONVERSATIONS}/{conversation_id}/messages"


def _body(text: str, client_message_id: str = "msg_1") -> bytes:
    return json.dumps(
        {"clientMessageId": client_message_id, "text": text, "attachments": []}
    ).encode("utf-8")


async def _drain(adapter) -> None:
    while adapter._background_tasks:
        await asyncio.gather(*list(adapter._background_tasks), return_exceptions=True)


def _recorder(adapter) -> list:
    dispatched: list = []

    async def _record(event):
        dispatched.append(event)

    adapter.handle_message = _record
    return dispatched


def test_reserved_new_command_is_never_handed_to_the_agent(tmp_path):
    """Hermes runs its own reset on `/new`; forwarding it would wipe the source."""
    async def scenario():
        store = _SessionStoreDouble()
        adapter = _adapter(_make_core(tmp_path), store)
        dispatched = _recorder(adapter)

        await adapter._notify_agent_inbound(
            _messages_path("conv_source"), _body("/new", "msg_new"), {}, ACCOUNT_ID,
        )

        assert dispatched == []
        assert store.calls == []
    asyncio.run(scenario())


def test_a_user_message_binds_the_conversation_and_routes_to_its_session(tmp_path):
    async def scenario():
        store = _SessionStoreDouble()
        core = _make_core(tmp_path)
        conversation = _seed_conversation(core, "cconv_alpha")
        adapter = _adapter(core, store)
        dispatched = _recorder(adapter)

        await adapter._notify_agent_inbound(
            _messages_path(conversation), _body("你好"), {}, ACCOUNT_ID,
        )

        assert [event.source.chat_id for event in dispatched] == [conversation]
        assert store.calls == [(conversation, False)]
        binding = _binding(core, conversation)
        assert binding["agentSessionId"] == store.sessions[conversation]
        assert binding["createdVia"] == "inbound-message"
    asyncio.run(scenario())


def test_two_conversations_never_share_one_agent_session(tmp_path):
    async def scenario():
        store = _SessionStoreDouble()
        core = _make_core(tmp_path)
        first_conversation = _seed_conversation(core, "cconv_a")
        second_conversation = _seed_conversation(core, "cconv_b")
        adapter = _adapter(core, store)

        first = await adapter._ensure_agent_session(
            first_conversation, ACCOUNT_ID, force_new=False, created_via="conversation-read",
        )
        second = await adapter._ensure_agent_session(
            second_conversation, ACCOUNT_ID, force_new=False, created_via="conversation-read",
        )

        assert first != second
        assert _binding(core, first_conversation)["agentSessionId"] == first
        assert _binding(core, second_conversation)["agentSessionId"] == second
    asyncio.run(scenario())


def test_reopening_a_conversation_reuses_the_session_it_already_has(tmp_path):
    """Switching back must resume the memory, not start a second one."""
    async def scenario():
        store = _SessionStoreDouble()
        core = _make_core(tmp_path)
        conversation = _seed_conversation(core, "cconv_open")
        adapter = _adapter(core, store)

        first = await adapter._ensure_agent_session(
            conversation, ACCOUNT_ID, force_new=False, created_via="conversation-read",
        )
        second = await adapter._ensure_agent_session(
            conversation, ACCOUNT_ID, force_new=False, created_via="conversation-read",
        )

        assert first == second == store.sessions[conversation]
        assert [call[1] for call in store.calls] == [False, False]
    asyncio.run(scenario())


def test_a_bound_conversation_never_changes_its_agent_session(tmp_path):
    """Contract §7.1: switching, reconnecting or replaying must not rebind it."""
    async def scenario():
        store = _SessionStoreDouble()
        core = _make_core(tmp_path)
        conversation = _seed_conversation(core, "cconv_stable")
        adapter = _adapter(core, store)

        first = await adapter._ensure_agent_session(
            conversation, ACCOUNT_ID, force_new=False, created_via="conversation-read",
        )
        # A slower ensure reports a different session for the same conversation;
        # the binding written first is the one that stays.
        second = await adapter._ensure_agent_session(
            conversation, ACCOUNT_ID, force_new=True, created_via="new-command",
        )

        assert second is not None and second != first
        assert _binding(core, conversation)["agentSessionId"] == first
        assert store.calls[0] == (conversation, False)
    asyncio.run(scenario())


def test_a_created_conversation_gets_a_brand_new_agent_session(tmp_path):
    """`/new` means "inherit nothing", so the host session is forced new."""
    async def scenario():
        store = _SessionStoreDouble()
        core = _make_core(tmp_path)
        created = _seed_conversation(core, "cconv_created")
        adapter = _adapter(core, store)
        adapter._loop = asyncio.get_running_loop()

        adapter._bind_created_conversation(ACCOUNT_ID, {
            "outcome": "created-conversation",
            "conversationId": created,
        })
        await _drain(adapter)

        assert store.calls == [(created, True)]
        binding = _binding(core, created)
        assert binding["createdVia"] == "new-command"
        assert binding["agentSessionId"] == store.sessions[created]
    asyncio.run(scenario())


def test_a_command_result_without_a_created_conversation_binds_nothing(tmp_path):
    async def scenario():
        store = _SessionStoreDouble()
        core = _make_core(tmp_path)
        adapter = _adapter(core, store)
        adapter._loop = asyncio.get_running_loop()

        adapter._bind_created_conversation(ACCOUNT_ID, {"outcome": "rejected", "conversationId": "conv_x"})
        adapter._bind_created_conversation(ACCOUNT_ID, {"outcome": "created-conversation"})
        await _drain(adapter)

        assert store.calls == []
    asyncio.run(scenario())


def test_a_host_without_a_session_store_records_an_absent_binding(tmp_path):
    """No runtime behind the adapter means no session id — never an invented one."""
    async def scenario():
        core = _make_core(tmp_path)
        conversation = _seed_conversation(core, "cconv_no_store")
        adapter = _adapter(core, None)
        dispatched = _recorder(adapter)

        await adapter._notify_agent_inbound(
            _messages_path(conversation), _body("你好"), {}, ACCOUNT_ID,
        )

        # The Agent still answers the message; only its session id stays unknown.
        assert len(dispatched) == 1
        binding = _binding(core, conversation)
        assert binding is not None
        assert binding["agentSessionId"] is None
        assert binding["createdVia"] == "inbound-message"
    asyncio.run(scenario())


def test_opening_and_reading_a_conversation_both_name_it():
    """The phone switches by reading, so a timeline read is an open."""
    assert _conversation_id_of(f"{CONVERSATIONS}/conv_1") == "conv_1"
    assert _conversation_id_of(f"{CONVERSATIONS}/conv_1/messages") == "conv_1"
    assert _conversation_id_of(f"{CONVERSATIONS}/conv_1/generations/gen_1/cancel") is None
    assert _conversation_id_of(f"{CONVERSATIONS}/conv_1/attachments") is None
    assert _conversation_id_of(CONVERSATIONS) is None


def test_opening_a_conversation_over_http_binds_its_agent_session(tmp_path):
    """The switch the phone performs: read a conversation, get its own session."""
    aiohttp = pytest.importorskip("aiohttp")

    async def scenario():
        store = _SessionStoreDouble()
        core = _make_core(tmp_path)
        opened = _seed_conversation(core, "cconv_http")
        read_by_timeline = _seed_conversation(core, "cconv_http_timeline")

        def _verify(request):
            # The verified target mirrors the request the phone actually signed,
            # so the route under test is the route that was opened.
            return make_verified_request({
                "context": {
                    "accountId": ACCOUNT_ID, "deviceId": "dev_1", "sessionId": "sess_1",
                    "requestId": "req_open", "correlationId": "cor_open",
                    "pairingGeneration": 1, "grantRevision": 1,
                },
                "method": request.get("method"),
                "target": request.get("target"),
                "now": "2026-09-13T00:00:00.000Z",
            })

        adapter = _adapter(core, store, verify_request=_verify)
        assert await adapter.connect() is True
        try:
            port = adapter._site._server.sockets[0].getsockname()[1]
            async with aiohttp.ClientSession() as session:
                for conversation in (opened, read_by_timeline):
                    async with session.get(
                        f"http://127.0.0.1:{port}{CONVERSATIONS}/{conversation}"
                    ) as response:
                        assert response.status == 200
                    async with session.get(
                        f"http://127.0.0.1:{port}{_messages_path(conversation)}"
                    ) as response:
                        assert response.status == 200
                    await _await_binding(core, conversation)
        finally:
            await adapter.disconnect()

        for conversation in (opened, read_by_timeline):
            binding = _binding(core, conversation)
            assert binding["createdVia"] == "conversation-read"
            assert binding["agentSessionId"] == store.sessions[conversation]
        assert store.sessions[opened] != store.sessions[read_by_timeline]
    asyncio.run(scenario())


async def _await_binding(core, conversation_id: str, timeout: float = 5.0) -> None:
    """The binding is written off the response path; wait for it instead of racing."""
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if _binding(core, conversation_id) is not None:
            return
        await asyncio.sleep(0.05)
    raise AssertionError(f"no Agent session binding was recorded for {conversation_id}")
