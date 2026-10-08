"""Real HTTP controls for admission isolation and reset/issuance fencing."""
import asyncio
import copy
import json
import sys
import threading
from pathlib import Path

import aiohttp

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from open_android_intelligence_gateway.adapter import AccountPasswordVerifier, GatewayRequestVerifier, OpenAndroidPlatformAdapter
from open_android_intelligence_gateway.admin import HostApiCompatibility, create_admin_service
from open_android_intelligence_gateway.core import create_gateway_core
from open_android_intelligence_gateway.http import create_gateway_exposure
from open_android_intelligence_gateway.plugin import GatewayServices
from test_support import contract_root, make_secret_store

INSTALLATION = {"installationId": "install_1", "displayName": "Phone", "devicePublicKey": "A" * 43}
HOST_API = HostApiCompatibility("1.0.0", "1.0.0", "0123456789abcdef0123456789abcdef01234567")


def setup(tmp_path):
    core = create_gateway_core(storage_root=tmp_path, secret_store=make_secret_store())
    core.credential_verifier = AccountPasswordVerifier(core)
    admin = create_admin_service(core=core, host_version="1.0.0", host_api=HOST_API)
    for username in ("alice", "bob"):
        assert admin.create_account({"accountId": username, "password": "old password", "localConfirmation": True})["ok"]
    exposure = create_gateway_exposure("host-route", core=core, host_version="1.0.0", host_api=HOST_API, verify_request=GatewayRequestVerifier(core))
    config = type("Config", (), {"extra": {"port": 0, "host": "127.0.0.1", "account_id": "alice"}})()
    return core, admin, OpenAndroidPlatformAdapter(config, GatewayServices(core, admin, exposure))


def negotiation(core, username="alice"):
    vectors = contract_root() / "vectors/protocol-negotiation.json"
    body = copy.deepcopy(json.loads(vectors.read_text())["cases"][0]["input"]["value"])
    body["negotiationId"] = "neg_" + username
    body["schemaHashes"]["core"] = core.contracts.core_schema_hash
    body["client"]["installationId"] = INSTALLATION["installationId"]
    return body


def password_body(username="alice", password="old password"):
    return {"negotiationId": "neg_" + username, "username": username, "password": password, "installation": INSTALLATION}


def test_raw_password_admission_isolates_accounts_and_trusts_only_transport_peer(tmp_path):
    async def scenario():
        core, _, adapter = setup(tmp_path)
        assert await adapter.connect()
        port = adapter._site._server.sockets[0].getsockname()[1]
        origin = f"http://127.0.0.1:{port}/open-android-intelligence/v2"
        try:
            async with aiohttp.ClientSession() as client:
                async def post(path, body, peer="203.0.113.1"):
                    async with client.post(origin + path, json=body, headers={"X-Forwarded-For": peer}) as response:
                        await response.read()
                        return response.status
                for username in ("alice", "bob"):
                    assert await post("/negotiate", negotiation(core, username)) == 200
                for body in ({}, [], {"username": "alice"}):
                    for _ in range(10):
                        assert await post("/sessions/password", body) == 400
                assert await post("/sessions/password", password_body()) == 200
                for _ in range(29):
                    assert await post("/sessions/password", password_body(password="wrong password")) == 401
                assert await post("/sessions/password", password_body(), "198.51.100.2") == 429
                assert await post("/sessions/password", password_body("bob")) == 200
                assert set(core._password_attempts) == {("127.0.0.1", "alice"), ("127.0.0.1", "bob")}
        finally:
            await adapter.disconnect()
    asyncio.run(scenario())


def test_reset_fences_real_inflight_old_password_validation_before_issuance(tmp_path):
    async def scenario():
        core, admin, adapter = setup(tmp_path)
        verified, release = threading.Event(), threading.Event()

        class ScheduledVerifier(AccountPasswordVerifier):
            def verify(self, *args):
                result = super().verify(*args)
                assert result is True
                verified.set()
                assert release.wait(10)
                return result

        core.credential_verifier = ScheduledVerifier(core)
        assert await adapter.connect()
        port = adapter._site._server.sockets[0].getsockname()[1]
        origin = f"http://127.0.0.1:{port}/open-android-intelligence/v2"
        try:
            async with aiohttp.ClientSession() as client:
                async with client.post(origin + "/negotiate", json=negotiation(core)) as response:
                    assert response.status == 200
                pending = asyncio.create_task(client.post(origin + "/sessions/password", json=password_body()))
                assert await asyncio.to_thread(verified.wait, 10)
                assert admin.reset_password({"accountId": "alice", "password": "new password", "localConfirmation": True})["ok"]
                release.set()
                async with await pending as response:
                    assert response.status == 401
                    assert (await response.json())["error"]["code"] == "AUTHENTICATION_FAILED"
                account = core.open_gateway_account("alice")
                try:
                    for table in ("access_sessions", "refresh_credentials", "device_keys"):
                        assert account.store.database.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
                finally:
                    account.close()
                core.credential_verifier = AccountPasswordVerifier(core)
                async with client.post(origin + "/sessions/password", json=password_body()) as response:
                    assert response.status == 401
                async with client.post(origin + "/sessions/password", json=password_body(password="new password")) as response:
                    assert response.status == 200
                    bundle = (await response.json())["data"]
                body = {"negotiationId": "neg_alice", "accountId": "alice", "installationId": INSTALLATION["installationId"],
                        "deviceId": bundle["deviceId"], "refreshCredential": bundle["refreshCredential"]}
                async with client.post(origin + "/sessions/refresh", json=body) as response:
                    assert response.status == 200
        finally:
            release.set()
            await adapter.disconnect()
    asyncio.run(scenario())
