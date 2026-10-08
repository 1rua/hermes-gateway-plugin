"""PR #6 review: cancellation, recursive schemas, grant and identity fences."""
import asyncio
import hashlib
import sys
from dataclasses import replace
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from open_android_intelligence_gateway import device_tools
from open_android_intelligence_gateway.admin import create_admin_service, VERIFIED_HERMES_HOST_API
from open_android_intelligence_gateway.core import create_gateway_core, GatewayError, VerifiedRequestContext, _jcs
from test_support import make_secret_store, seed_event_session, make_verified_request


def register(account, schema, risk="read"):
    binding = {
        "pluginId": "org.example.actual", "authorKeyId": "sha256:" + "a" * 64,
        "capabilityId": "org.example.actual.read", "capabilityVersion": "2.0.0",
        "schemaSha256": "sha256:" + hashlib.sha256(_jcs(schema).encode()).hexdigest(),
        "schema": schema, "risk": risk,
    }
    account.device_requests.capabilities.register("dev_1", 1, 1, [binding])
    return binding


@pytest.mark.parametrize("state,expected", [("pending", "cancelled"), ("claimed", "cancel_requested"), ("succeeded", "succeeded")])
def test_host_task_cancellation_fences_pending_and_claimed_without_erasing_a_finished_result(tmp_path, state, expected):
    core = create_gateway_core(tmp_path, secret_store=make_secret_store())
    seed_event_session(core)
    account = core.open_gateway_account("acct_alice")
    try:
        binding = register(account, {"type": "object", "additionalProperties": False})
    finally:
        account.close()

    async def scenario():
        token = device_tools.trusted_turn.set({
            "core": core, "accountId": "acct_alice", "deviceId": "dev_1",
            "pairingGeneration": 1, "grantRevision": 1, "conversationId": "conv_native",
            "messageId": "msg_native", "sessionId": "native_one",
        })
        try:
            task = asyncio.create_task(device_tools.execute(core, {
                "capabilityId": binding["capabilityId"], "capabilityVersion": "2.0.0", "parameters": {},
            }, session_id="native_one"))
            await asyncio.sleep(0)  # The tool is now suspended in its result poll.
            account = core.open_gateway_account("acct_alice")
            try:
                request_id = account.store.database.execute("SELECT request_id FROM device_requests").fetchone()[0]
                if state != "pending":
                    claim = account.device_requests.claim(request_id, "dev_1", 1, 1, "cor_claim")
                    if state == "succeeded":
                        account.device_requests.submit_result(request_id, "dev_1", 1, 1, claim["claimId"],
                            {"outcome": "succeeded", "data": {"actual": True}}, "cor_result")
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
                assert account.device_requests.get(request_id)["state"] == expected
                cancellations = [e for e in account.events.read_after(None) if e["eventType"] == "device.request.cancel.requested"]
                assert len(cancellations) == (0 if state == "succeeded" else 1)
                if state == "pending":
                    with pytest.raises(GatewayError):
                        account.device_requests.claim(request_id, "dev_1", 1, 1, "cor_late")
                if state == "succeeded":
                    assert account.device_requests.read_result(request_id, claim["claimId"])["data"] == {"actual": True}
            finally:
                account.close()
        finally:
            device_tools.trusted_turn.reset(token)
    asyncio.run(scenario())


def test_recursive_local_schema_registers_and_validates_finite_device_data(tmp_path):
    core = create_gateway_core(tmp_path, secret_store=make_secret_store())
    seed_event_session(core)
    account = core.open_gateway_account("acct_alice")
    schema = {
        "type": "object", "additionalProperties": False, "required": ["tree"],
        "properties": {"tree": {"$ref": "#/$defs/node"}},
        "$defs": {"node": {"type": "object", "additionalProperties": False, "required": ["value"],
            "properties": {"value": {"type": "integer"}, "children": {"type": "array", "items": {"$ref": "#/$defs/node"}}}}},
    }
    try:
        binding = register(account, schema)
        def enqueue(request_id, parameters):
            return account.device_requests.enqueue(request_id, "dev_1", 1, 1, "read",
                {"id": binding["capabilityId"], "version": "2.0.0"},
                {"pluginId": binding["pluginId"], "authorKeyId": binding["authorKeyId"]}, parameters, "cor_recursive")
        assert enqueue("recursive_ok", {"tree": {"value": 1, "children": [{"value": 2}]}})["state"] == "pending"
        with pytest.raises(GatewayError, match="SCHEMA_INVALID"):
            enqueue("recursive_bad", {"tree": {"value": 1, "children": [{"value": "wrong"}]}})
        for ref in ("https://other.example/schema", "#/$defs/missing", "#/$defs/bad~2"):
            with pytest.raises(GatewayError, match="SCHEMA_INVALID"):
                register(account, {**schema, "properties": {"tree": {"$ref": ref}}})
    finally:
        account.close()


def negotiation(core, offered):
    return {
        "negotiationId": "neg_review", "protocol": {"major": 2, "minor": 1},
        "client": {"installationId": "install_one", "appVersion": "2.1.0", "platform": "android", "platformApi": 35},
        "schemaHashes": {"core": core.contracts.core_schema_hash},
        "features": {"auth": ["password"], "messages": ["chat-v1"], "attachments": ["staged-sha256-v1"],
            "events": ["sse-cursor-v1"], "deviceRequests": ["risk-queue-v1"], "conversationUi": offered},
    }


def test_invite_and_negotiation_use_the_same_rotated_account_identity(tmp_path):
    core = create_gateway_core(tmp_path, secret_store=make_secret_store())
    account = core.open_gateway_account("acct_alice")
    try:
        for key, value in (("deployment_id", "deploy_rotated"), ("tls_spki_sha256", "sha256:" + "b" * 64)):
            account.store.database.execute("INSERT OR REPLACE INTO account_metadata(key,value) VALUES (?,?)", (key, value))
        identity = core._build_negotiation_response(negotiation(core, []), account)["gatewayIdentity"]
    finally:
        account.close()
    admin = create_admin_service(core=core, host_version="0.20.0", host_api=VERIFIED_HERMES_HOST_API)
    result = admin.create_pairing_invite({"accountId": "acct_alice", "gatewayUrl": "https://gateway.example", "localConfirmation": True})
    query = parse_qs(urlparse(result["data"]["qrPayload"]).query)
    assert query["identityFingerprint"] == ["sha256:" + hashlib.sha256(_jcs(identity).encode()).hexdigest()]


@pytest.mark.parametrize("offered", [[], ["message-batches-v1"], ["newline-v1"], ["message-batches-v1", "newline-v1"]])
def test_batch_and_join_mode_are_independently_intersected(tmp_path, offered):
    core = create_gateway_core(tmp_path, secret_store=make_secret_store())
    features = core._build_negotiation_response(negotiation(core, offered))["features"]
    assert features.get("conversationUi", []) == offered


def test_device_request_lookup_fences_the_grant_revision_before_exposing_parameters(tmp_path):
    core = create_gateway_core(tmp_path, secret_store=make_secret_store())
    seed_event_session(core)
    context = VerifiedRequestContext(account_id="acct_alice", device_id="dev_1", session_id="sess_1",
        request_id="req_lookup", correlation_id="cor_lookup", pairing_generation=1, grant_revision=1)
    account = core.open_gateway_account("acct_alice")
    try:
        binding = register(account, {"type": "object", "additionalProperties": False})
        account.device_requests.enqueue("request_old", "dev_1", 1, 1, "read",
            {"id": binding["capabilityId"], "version": "2.0.0"},
            {"pluginId": binding["pluginId"], "authorKeyId": binding["authorKeyId"]}, {}, "cor_request")
        account.bump_grant_revision("dev_1", "cor_bump")
    finally:
        account.close()
    result = core.handle(make_verified_request({"method": "GET", "target": "/open-android-intelligence/v2/device-requests/request_old",
        "context": replace(context, grant_revision=2)}))
    assert result["error"]["code"] == "GRANT_STALE"
    assert "data" not in result


def test_rejected_capability_publications_and_replays_do_not_change_authorization(tmp_path):
    core = create_gateway_core(tmp_path, secret_store=make_secret_store())
    seed_event_session(core)
    context = VerifiedRequestContext(account_id="acct_alice",device_id="dev_1",session_id="sess_1",
        request_id="req_seed",correlation_id="cor_publication",pairing_generation=1,grant_revision=1)
    account = core.open_gateway_account("acct_alice")
    try:
        binding = register(account, {"type":"object","additionalProperties":False})
        account.device_requests.enqueue("request_existing","dev_1",1,1,"read",
            {"id":binding["capabilityId"],"version":binding["capabilityVersion"]},
            {"pluginId":binding["pluginId"],"authorKeyId":binding["authorKeyId"]},{},"cor_existing")
    finally:
        account.close()

    def snapshot():
        account = core.open_gateway_account("acct_alice")
        try:
            return {
                "revision": account.store.database.execute("SELECT grant_revision FROM device_keys WHERE device_id='dev_1'").fetchone()[0],
                "metadata": [tuple(row) for row in account.store.database.execute(
                    "SELECT key,value FROM account_metadata WHERE key IN ('device-capabilities:dev_1','device-grant-digest:dev_1') ORDER BY key").fetchall()],
                "events": [tuple(row) for row in account.store.database.execute("SELECT * FROM events ORDER BY rowid").fetchall()],
                "audit": [tuple(row) for row in account.store.database.execute("SELECT * FROM audit_events ORDER BY rowid").fetchall()],
                "request": account.device_requests.get("request_existing"),
            }
        finally:
            account.close()

    before = snapshot()
    unsupported = {**binding["schema"],"not":{}}
    oversized = {**binding["schema"],"description":"汉"*90_000}
    invalid = [None,[None],[{**binding,"risk":{}}],[{**binding,"schemaSha256":"sha256:"+"0"*64}],
        [{**binding,"schema":unsupported,"schemaSha256":"sha256:"+hashlib.sha256(_jcs(unsupported).encode()).hexdigest()}],
        [binding]*129,[{**binding,"schema":oversized,"schemaSha256":"sha256:"+hashlib.sha256(_jcs(oversized).encode()).hexdigest()}]]
    target = "/open-android-intelligence/v2/pairings/current/capabilities"
    for index, bindings in enumerate(invalid):
        request_id = f"req_bad_{index}"
        request = make_verified_request({"method":"POST","target":target,
            "context":replace(context,request_id=request_id),"idempotencyKey":request_id,
            "body":{"bindings":bindings,"expectedGrantRevision":1,"localGrantRevision":2}})
        failed = core.handle(request)
        assert failed["error"]["code"] == "SCHEMA_INVALID"
        assert core.handle(request) == failed
        assert snapshot() == before
    lookup = core.handle(make_verified_request({"method":"GET",
        "target":"/open-android-intelligence/v2/device-requests/request_existing","context":context}))
    assert lookup["data"]["request"]["state"] == "pending"
    result = core.handle(make_verified_request({"method":"POST","target":target,
        "context":replace(context,request_id="req_valid"),"idempotencyKey":"req_valid",
        "body":{"bindings":[binding],"expectedGrantRevision":1,"localGrantRevision":2}}))
    assert result["data"]["grantRevision"] == 2
    account = core.open_gateway_account("acct_alice")
    try:
        assert account.device_requests.capabilities.list("dev_1",1,2) == [binding]
        assert len([event for event in account.events.read_after(None) if event["eventType"] == "pairing.grant.changed"]) == 1
    finally:
        account.close()
