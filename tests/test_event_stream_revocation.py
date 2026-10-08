"""Real signed transport regression for the event-stream authorization boundary."""
import asyncio
import base64
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
import aiohttp
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from open_android_intelligence_gateway.adapter import AccountPasswordVerifier, GatewayRequestVerifier, OpenAndroidPlatformAdapter
from open_android_intelligence_gateway.admin import HostApiCompatibility, create_admin_service
from open_android_intelligence_gateway.core import create_gateway_core, iso_millis, request_signature_preimage
from open_android_intelligence_gateway.http import create_gateway_exposure
from open_android_intelligence_gateway.plugin import GatewayServices
from test_support import make_secret_store

API = HostApiCompatibility("1.0.0", "1.0.0", "0123456789abcdef0123456789abcdef01234567")
TARGET = "/open-android-intelligence/v2/events"


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def headers(private, session):
    timestamp, nonce = iso_millis(datetime.now(timezone.utc)), b64(secrets.token_bytes(16))
    fields = {"method": "GET", "target": TARGET, "accountId": "alice", "deviceId": session["deviceId"],
              "sessionId": session["sessionId"], "requestId": "req_" + secrets.token_hex(8),
              "timestamp": timestamp, "nonce": nonce, "bodyHex": ""}
    return {"Authorization": "Bearer " + session["accessToken"], "Accept": "text/event-stream",
            "X-Open-Android-Intelligence-Protocol": "2.1",
            **{"X-Open-Android-Intelligence-" + name: fields[key] for name, key in [
                ("Account", "accountId"), ("Device", "deviceId"), ("Session", "sessionId"),
                ("Request-Id", "requestId"), ("Timestamp", "timestamp"), ("Nonce", "nonce")]},
            "X-Open-Android-Intelligence-Signature": b64(private.sign(request_signature_preimage(fields)))}


@pytest.mark.parametrize("transport", ["ws", "sse"])
@pytest.mark.parametrize("action", ["session", "unpair", "delete", "expiry"])
def test_signed_stream_stops_before_delivering_private_events(tmp_path, transport, action):
    async def scenario():
        core = create_gateway_core(storage_root=tmp_path, secret_store=make_secret_store())
        core.credential_verifier = AccountPasswordVerifier(core)
        admin = create_admin_service(core=core, host_version="1.0.0", host_api=API)
        assert admin.create_account({"accountId": "alice", "password": "fixture", "localConfirmation": True})["ok"]
        private = Ed25519PrivateKey.generate()
        public = b64(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        account = core.open_gateway_account("alice")
        try:
            first = account.sessions.create_password_session("alice", "fixture", {"installationId": "install_one", "displayName": "Phone", "devicePublicKey": public}, "cor_login_one")
            other = account.sessions.create_password_session("alice", "fixture", {"installationId": "install_two", "displayName": "Other phone", "devicePublicKey": public}, "cor_login_two")
        finally:
            account.close()
        exposure = create_gateway_exposure("host-route", core=core, host_version="1.0.0", host_api=API, verify_request=GatewayRequestVerifier(core))
        config = type("Config", (), {"extra": {"port": 0, "host": "127.0.0.1", "account_id": "alice"}})()
        adapter = OpenAndroidPlatformAdapter(config, GatewayServices(core, admin, exposure))
        assert await adapter.connect()
        port = adapter._site._server.sockets[0].getsockname()[1]
        try:
            async with aiohttp.ClientSession() as client:
                url = f"http://127.0.0.1:{port}{TARGET}"
                stream = await (client.ws_connect(url, headers=headers(private, first)) if transport == "ws" else client.get(url, headers=headers(private, first)))
                control = await client.ws_connect(url, headers=headers(private, other))
                try:
                    account = core.open_gateway_account("alice")
                    try:
                        with account.store.transaction():
                            account.events.append("gateway.notice", "cor_before", {"noticeCode": "BEFORE"})
                        if transport == "ws":
                            assert "BEFORE" in (await asyncio.wait_for(stream.receive(), 3)).data
                        else:
                            while b"BEFORE" not in await asyncio.wait_for(stream.content.readline(), 3):
                                pass
                        assert "BEFORE" in (await asyncio.wait_for(control.receive(), 3)).data
                        if action == "session":
                            account.sessions.revoke_session(first["sessionId"], "cor_revoke")
                        elif action == "unpair":
                            account.revoke_pairing(first["deviceId"], "cor_unpair")
                        elif action == "expiry":
                            account.store.database.execute("UPDATE access_sessions SET expires_at = '2000-01-01T00:00:00.000Z' WHERE session_id = ?", (first["sessionId"],))
                        else:
                            core.delete_gateway_account("alice")
                        if action != "delete":
                            with account.store.transaction():
                                account.events.append("gateway.notice", "cor_after", {"noticeCode": "PRIVATE-AFTER"})
                    finally:
                        account.close()
                    if transport == "ws":
                        stopped = await asyncio.wait_for(stream.receive(), 3)
                        assert stopped.type in {aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.CLOSING}
                    else:
                        remaining = await asyncio.wait_for(stream.content.read(), 3)
                        assert b"PRIVATE-AFTER" not in remaining
                    if action != "delete":
                        while True:
                            delivered = await asyncio.wait_for(control.receive(), 3)
                            assert delivered.type == aiohttp.WSMsgType.TEXT
                            if "PRIVATE-AFTER" in delivered.data:
                                break
                finally:
                    if transport == "ws": await stream.close()
                    else: stream.close()
                    await control.close()
        finally:
            await adapter.disconnect()
    asyncio.run(scenario())
