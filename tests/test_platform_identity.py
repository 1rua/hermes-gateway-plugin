"""平台更名的普通回归：保留兼容入口，不能伪装成 LOCAL。"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from aiohttp import ClientSession

from open_android_intelligence_gateway import adapter as adapter_module
from open_android_intelligence_gateway.admin import VERIFIED_HERMES_HOST_API
from open_android_intelligence_gateway.plugin import register
from open_android_intelligence_gateway.core import GatewayError
from test_support import make_secret_store


class NativeSurface:
    def __init__(self, root):
        self.plugin_data_dir = root
        self.secret_store = make_secret_store()
        self.host_version = "0.21.3"
        self.host_api = VERIFIED_HERMES_HOST_API
        self.platforms = {}

    def register_platform(self, name, label, adapter_factory, check_fn, **options):
        self.platforms[name] = (adapter_factory, options)


def test_native_registration_shares_one_adapter_with_legacy_names(tmp_path):
    context = NativeSurface(tmp_path)
    register(context)
    expected = {"open-android-intelligence-gateway", "open_android", "open_android_intelligence"}
    assert set(context.platforms) == expected
    config = SimpleNamespace(extra={"host": "127.0.0.1", "port": 0})
    adapters = [factory(config) for factory, _ in context.platforms.values()]
    assert len({id(adapter) for adapter in adapters}) == 1
    assert adapters[0].platform.value == "open-android-intelligence-gateway"


def test_unknown_canonical_platform_fails_without_local_fallback(tmp_path, monkeypatch):
    class RefusedPlatform:
        LOCAL = SimpleNamespace(value="local")

        def __init__(self, value):
            raise ValueError("未注册的平台")

    monkeypatch.setattr(adapter_module, "Platform", RefusedPlatform)
    with pytest.raises(ValueError, match="未注册的平台"):
        adapter_module.OpenAndroidPlatformAdapter(SimpleNamespace(extra={}), SimpleNamespace(core=SimpleNamespace(storage_root=tmp_path)))


def test_native_registration_error_is_reported_instead_of_swallowed(tmp_path):
    class RefusedSurface(NativeSurface):
        def register_platform(self, name, label, adapter_factory, check_fn, **options):
            raise RuntimeError("宿主拒绝平台注册")

    with pytest.raises(RuntimeError, match="宿主拒绝平台注册"):
        register(RefusedSurface(tmp_path))


def test_legacy_entries_open_and_close_one_real_http_listener(tmp_path):
    async def scenario():
        context = NativeSurface(tmp_path)
        register(context)
        config = SimpleNamespace(extra={"host": "127.0.0.1", "port": 0})
        adapters = [factory(config) for factory, _ in context.platforms.values()]
        adapter = adapters[0]
        adapter._port = 0
        try:
            assert all(await asyncio.gather(*(item.connect() for item in adapters)))
            assert len(adapter._runner.sites) == 1
            assert len(adapter.services.core._event_sinks) == 1
            assert len(adapter._background_tasks) == 1
            port = adapter._site._server.sockets[0].getsockname()[1]
            async with ClientSession() as client:
                async with client.get(f"http://127.0.0.1:{port}/health") as response:
                    assert response.status == 200 and await response.text() == "ok"
        finally:
            await asyncio.gather(*(item.disconnect() for item in adapters))
        assert not adapter._running and adapter._site is None
        assert not adapter.services.core._event_sinks
        assert adapter._maintenance_task is None

    asyncio.run(scenario())


def test_conversation_source_cache_is_separated_by_account(tmp_path):
    context = NativeSurface(tmp_path)
    register(context)
    factory, _ = context.platforms["open-android-intelligence-gateway"]
    adapter = factory(SimpleNamespace(extra={}))
    adapter._conversation_platforms[("fixture-one", "same-conversation")] = "open_android"
    assert adapter._agent_source("same-conversation", "fixture-one").platform.value == "open_android"
    assert adapter._agent_source("same-conversation", "fixture-two").platform.value == "open-android-intelligence-gateway"


def test_unknown_agent_binding_stops_ensure_without_creating_a_replacement(tmp_path, monkeypatch):
    context = NativeSurface(tmp_path)
    register(context)
    factory, _ = context.platforms["open-android-intelligence-gateway"]
    adapter = factory(SimpleNamespace(extra={}))
    adapter.set_session_store(SimpleNamespace())
    written = []

    def refused(*args):
        raise GatewayError("HOST_INCOMPATIBLE", {"reason": "UNRESOLVED_AGENT_SESSION_BINDING"})

    monkeypatch.setattr(adapter, "_lookup_or_create_agent_session", refused)
    monkeypatch.setattr(adapter, "_record_agent_session_binding", lambda *args: written.append(args))
    with pytest.raises(GatewayError, match="HOST_INCOMPATIBLE"):
        asyncio.run(adapter._ensure_agent_session("fixture-conversation", "fixture-user", force_new=False, created_via="conversation-read"))
    assert not written


@pytest.mark.parametrize("platform, user, chat, sid, key", [
    ("local", "fixture-user", "fixture-conversation", "same-session", "same-key"),
    ("unknown", "fixture-user", "fixture-conversation", "same-session", "same-key"),
    ("open_android", "another-user", "fixture-conversation", "same-session", "same-key"),
    ("open_android", "fixture-user", "another-conversation", "same-session", "same-key"),
    ("open_android", "fixture-user", "fixture-conversation", "another-session", "same-key"),
    ("open_android", "fixture-user", "fixture-conversation", "same-session", "another-key"),
])
def test_mismatched_legacy_binding_cannot_claim_a_history_route(tmp_path, platform, user, chat, sid, key):
    context = NativeSurface(tmp_path)
    register(context)
    factory, _ = context.platforms["open-android-intelligence-gateway"]
    adapter = factory(SimpleNamespace(extra={}))
    entry = SimpleNamespace(origin=SimpleNamespace(platform=SimpleNamespace(value=platform), user_id=user, chat_id=chat), session_id=sid, session_key=key)
    with pytest.raises(GatewayError, match="HOST_INCOMPATIBLE"):
        adapter._remember_agent_source(None, entry, "fixture-conversation", "fixture-user", "same-session", "same-key")
    assert not adapter._conversation_platforms
