"""用真实 Hermes 在临时 home 验证平台身份、共享监听与历史连续性。"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import socket
import sqlite3
import sys
import tempfile
from datetime import datetime
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host-root", type=Path, required=True)
    parser.add_argument("--contract-root", type=Path, required=True)
    parser.add_argument("--plugin-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--config-mode", choices=("mixed", "legacy", "legacy-alternate", "disabled"), default="mixed")
    args = parser.parse_args()
    home = Path(tempfile.mkdtemp(prefix="oai-hermes-platform-"))
    (home / "plugins").mkdir()
    (home / "plugins" / "open-android-intelligence-gateway").symlink_to(args.plugin_root.resolve())
    modes = {
        "mixed": [("open_android", True, 18672), ("open_android_intelligence", True, 18673), ("open-android-intelligence-gateway", True, 18671)],
        "legacy": [("open_android", True, 18672)],
        "legacy-alternate": [("open_android_intelligence", True, 18673)],
        "disabled": [("open-android-intelligence-gateway", False, 18671)],
    }
    platform_yaml = "".join(
        f"  {name}:\n    enabled: {'true' if enabled else 'false'}\n    host: 127.0.0.1\n    port: {port}\n"
        for name, enabled, port in modes[args.config_mode]
    )
    (home / "config.yaml").write_text(
        "plugins:\n  enabled: [open-android-intelligence-gateway]\n"
        "gateway:\n  multiplex_profiles: false\n"
        "platforms:\n" + platform_yaml,
        encoding="utf-8",
    )
    os.environ["HERMES_HOME"] = str(home)
    os.environ["OPEN_ANDROID_GATEWAY_CONTRACT_ROOT"] = str(args.contract_root.resolve())
    os.environ["OPEN_ANDROID_INTELLIGENCE_GATEWAY_MASTER_KEY_FILE"] = str(home / "master.key")
    sys.path.insert(0, str(args.host_root.resolve()))
    sys.path.insert(0, str(args.plugin_root.resolve()))

    import hermes_cli
    from aiohttp import ClientSession
    from gateway.config import Platform, load_gateway_config
    from gateway.run import GatewayRunner
    from gateway.session import SessionSource, build_session_key
    from hermes_cli.plugins import get_plugin_manager
    from open_android_intelligence_gateway.core import GatewayError

    names = ("open-android-intelligence-gateway", "open_android", "open_android_intelligence")
    manager = get_plugin_manager()
    manager.discover_and_load()
    assert any(p["name"] == names[0] and p["enabled"] and p["error"] is None for p in manager.list_plugins())
    settings = load_gateway_config()
    if args.config_mode == "disabled":
        assert not any(settings.platforms.get(Platform(name)) and settings.platforms[Platform(name)].enabled for name in names)
        print(json.dumps({"result": "PASS", "hermes": hermes_cli.__version__, "checks": ["兼容名称不会绕过显式停用"], "fixture": str(home)}, ensure_ascii=False))
        return
    assert {name for name in names if settings.platforms[Platform(name)].enabled} == set(names)
    runner = GatewayRunner(settings)
    adapters = []
    for name in names:
        adapter = runner._create_adapter(Platform(name), settings.platforms[Platform(name)])
        assert adapter is not None, f"{name} 的适配器加载失败"
        runner._wire_adapter_handlers(adapter)
        runner.adapters[Platform(name)] = adapter
        adapters.append(adapter)
    assert len({id(adapter) for adapter in adapters}) == 1, "兼容入口必须共享同一实例"
    adapter = adapters[0]
    assert adapter.platform.value == names[0], "主适配器不能退回 LOCAL"
    expected_port = {"mixed": 18671, "legacy": 18672, "legacy-alternate": 18673}[args.config_mode]
    assert adapter._port == expected_port, f"监听器必须采用明确选择的配置：{adapter._port} != {expected_port}"
    assert adapter._session_store is runner.session_store
    assert adapter._message_handler is not None and adapter._fatal_error_handler is not None
    config_before = (home / "config.yaml").read_bytes()
    database = runner.session_store._db

    def seed_route(platform: str, cid: str, sid: str, user: str, *, legacy_json: bool = False) -> str:
        key = f"agent:main:{platform}:dm:{cid}"
        now = datetime.now().isoformat()
        origin = {"platform": platform, "chat_id": cid, "user_id": user, "chat_type": "dm"}
        raw = {"session_key": key, "session_id": sid, "created_at": now, "updated_at": now, "origin": origin, "platform": platform}
        database.create_session(sid, platform)
        database.append_message(sid, "user", "历史哨兵：保持原会话", platform_message_id=f"seed-{sid}")
        if legacy_json:
            path = home / "sessions" / "sessions.json"
            path.parent.mkdir(exist_ok=True)
            records = json.loads(path.read_text()) if path.exists() else {}
            records[key] = raw
            path.write_text(json.dumps(records), encoding="utf-8")
        else:
            database.save_gateway_routing_entry(key, json.dumps(raw), scope=str(home / "sessions"))
        assert SessionSource.from_dict(origin).platform.value == platform
        return key

    route_keys = []
    for alias in names[1:]:
        for legacy_json in (False, True):
            cid = f"fixture-{alias}-{'json' if legacy_json else 'db'}"
            key = seed_route(alias, cid, cid, "fixture-user", legacy_json=legacy_json)
            route_keys.append((key, cid))
    for key, sid in route_keys:
        entry = runner.session_store.lookup_by_session_key(key)
        assert entry is not None and entry.session_id == sid, "旧路由不得被跳过"
        assert entry.session_key == key and build_session_key(entry.origin) == key
        assert runner.session_store.get_or_create_session(entry.origin).session_id == sid
        assert database.get_messages(sid)[0]["content"] == "历史哨兵：保持原会话"

    async def check() -> None:
        adapter._port = 0
        assert all(await asyncio.gather(*(item.connect() for item in adapters)))
        assert len(adapter._runner.sites) == 1 and adapter._site is not None
        assert len(adapter.services.core._event_sinks) == 1
        assert adapter._maintenance_task is not None and not adapter._maintenance_task.done()
        assert len(adapter._background_tasks) == 1
        port = adapter._site._server.sockets[0].getsockname()[1]
        async with ClientSession() as client:
            async with client.get(f"http://127.0.0.1:{port}/health") as response:
                assert response.status == 200 and await response.text() == "ok"

        for alias in names[1:]:
            account = adapter.services.core.open_gateway_account("fixture-user")
            try:
                cid = account.conversations.create(f"fixture-{alias}", "兼容会话", f"cor-{alias}")["conversationId"]
                sid = f"native-{alias}"
                key = seed_route(alias, cid, sid, "fixture-user")
                account.agent_sessions.record(cid, "conversation-read")
                assert account.agent_sessions.attach(cid, sid, key)
                binding_before = account.agent_sessions.lookup(cid)
            finally:
                account.close()
            # 之前已经加载过，重新读取一份真实 SessionStore 以模拟重启。
            from gateway.session import SessionStore
            store = SessionStore(home / "sessions", settings)
            adapter.set_session_store(store)
            assert await adapter._ensure_agent_session(cid, "fixture-user", force_new=False, created_via="conversation-read") == sid
            source = adapter._agent_source(cid, "fixture-user")
            assert source.platform.value == alias and build_session_key(source) == key
            assert store.get_or_create_session(source).session_id == sid
            assert runner._transport_owner(source)[0] is adapter
            assert runner._delivery_adapter_for(source) is adapter
            assert runner._is_user_authorized(source)
            assert adapter._agent_source(cid, "another-user").platform.value == names[0]
            account = adapter.services.core.open_gateway_account("fixture-user")
            try:
                assert account.agent_sessions.lookup(cid) == binding_before
            finally:
                account.close()
            assert database.get_messages(sid)[0]["content"] == "历史哨兵：保持原会话"

        account = adapter.services.core.open_gateway_account("fixture-user")
        try:
            cid = account.conversations.create("fixture-local", "需要核查的历史", "cor-local")["conversationId"]
            key = seed_route("local", cid, "native-local", "fixture-user")
            account.agent_sessions.record(cid, "conversation-read")
            assert account.agent_sessions.attach(cid, "native-local", key)
        finally:
            account.close()
        adapter.set_session_store(SessionStore(home / "sessions", settings))
        with sqlite3.connect(home / "state.db") as conn:
            count_before = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        try:
            await adapter._ensure_agent_session(cid, "fixture-user", force_new=False, created_via="conversation-read")
        except GatewayError as error:
            assert error.code == "HOST_INCOMPATIBLE"
        else:
            raise AssertionError("LOCAL 来源不得自动认领")
        with sqlite3.connect(home / "state.db") as conn:
            assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == count_before
        assert database.get_messages("native-local")[0]["content"] == "历史哨兵：保持原会话"

        await asyncio.gather(*(item.disconnect() for item in adapters))
        assert adapter._site is None and adapter._runner is None and not adapter._running
        assert adapter._maintenance_task is None and not adapter.services.core._event_sinks
        with socket.socket() as blocked:
            blocked.bind(("127.0.0.1", 0))
            blocked.listen()
            adapter._port = blocked.getsockname()[1]
            assert not any(await asyncio.gather(*(item.connect() for item in adapters)))
            assert not adapter._running and not adapter.services.core._event_sinks
        await asyncio.gather(*(item.disconnect() for item in adapters))

    asyncio.run(check())
    assert (home / "config.yaml").read_bytes() == config_before, "验证不得重写配置"
    print(json.dumps({"result": "PASS", "hermes": hermes_cli.__version__, "checks": ["平台身份", "旧来源与JSON/SQLite路由", "单监听器及失败状态", "精确会话键与AgentID", "真实Runner授权及回送", "LOCAL历史拒绝自动认领", "配置保持不变"], "fixture": str(home)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
