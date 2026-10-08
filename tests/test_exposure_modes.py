import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from open_android_intelligence_gateway.admin import HostApiCompatibility
from open_android_intelligence_gateway.http import EXPOSURE_MODES, create_gateway_exposure
from open_android_intelligence_gateway.core import create_gateway_core
from test_support import (
    PasswordVerifierDouble,
    core_schema_hash,
    make_secret_store,
    make_verified_request,
    trust_core,
)


_real_create_gateway_core = create_gateway_core


def create_gateway_core(storage_root=None, **options):
    options.setdefault("secret_store", make_secret_store())
    return trust_core(_real_create_gateway_core(storage_root=storage_root, **options))


TEST_HOST_API = HostApiCompatibility(
    "1.0.0", "1.0.0", "0123456789abcdef0123456789abcdef01234567"
)


class FakeCore:
    def __init__(self):
        self.requests = []

    def handle(self, request):
        self.requests.append(request)
        context = request["context"] if isinstance(request, dict) else request.context
        request_id = context["requestId"] if isinstance(context, dict) else context.request_id
        correlation_id = context["correlationId"] if isinstance(context, dict) else context.correlation_id
        return {
            "requestId": request_id,
            "correlationId": correlation_id,
            "protocol": "2.1",
            "data": {"accepted": True, "target": request["target"] if isinstance(request, dict) else request.target},
        }


def _verified(target="/open-android-intelligence/v2/negotiate"):
    return make_verified_request({
        "context": {
            "accountId": "account-a", "deviceId": "device-a", "sessionId": "session-a",
            "requestId": "request-a", "correlationId": "correlation-a",
            "pairingGeneration": 1, "grantRevision": 1,
        },
        "method": "POST",
        "target": target,
        "body": {},
    })


def test_all_three_exposure_modes_share_routes_and_verified_core_result():
    results = []
    for mode in EXPOSURE_MODES:
        core = FakeCore()
        exposure = create_gateway_exposure(mode, core=core, host_version="1.0.0", host_api=TEST_HOST_API)
        route = next(item for item in exposure.routes if item.path == "/open-android-intelligence/v2/negotiate")
        response = route.handle({"verifiedRequest": _verified()})
        results.append(response)
        assert exposure.admin.remote_port is None
        assert exposure.admin.remotePort is None
    assert results[0] == results[1] == results[2]
    assert results[0]["statusCode"] == 200
    assert results[0]["body"]["data"] == {"accepted": True, "target": "/open-android-intelligence/v2/negotiate"}


def test_verified_route_rejects_a_plain_mapping_even_when_the_host_is_compatible():
    core = FakeCore()
    exposure = create_gateway_exposure(
        "host-route", core=core, host_version="1.0.0", host_api=TEST_HOST_API
    )
    route = next(item for item in exposure.routes if item.path == "/open-android-intelligence/v2/conversations")
    plain_mapping = {
        "context": {
            "accountId": "account-a", "deviceId": "device-a", "sessionId": "session-a",
            "requestId": "request-a", "correlationId": "correlation-a",
            "pairingGeneration": 1, "grantRevision": 1,
        },
        "method": "POST", "target": "/open-android-intelligence/v2/conversations",
        "body": {"clientConversationId": "conv_untrusted"},
    }

    response = route.handle({"verifiedRequest": plain_mapping})

    assert response["statusCode"] == 401
    assert response["body"]["error"]["code"] == "AUTHENTICATION_REQUIRED"
    assert core.requests == []


def test_incompatible_or_missing_host_fails_closed_before_core_for_each_mode():
    for host_version in (None, "not-a-version", "2.0.0"):
        for mode in EXPOSURE_MODES:
            core = FakeCore()
            exposure = create_gateway_exposure(mode, core=core, host_version=host_version)
            route = next(item for item in exposure.routes if item.path == "/open-android-intelligence/v2/negotiate")
            response = route.handle({"verifiedRequest": _verified()})
            assert response["statusCode"] == 503
            assert response["body"]["error"]["code"] == "HOST_INCOMPATIBLE"
            assert core.requests == []


class RawRequest:
    def __init__(self, body=b"{}", url="/open-android-intelligence/v2/negotiate"):
        self.method = "POST"
        self.url = url
        self.headers = {"content-type": "application/json"}
        self.rawHeaders = ("content-type", "application/json")
        self.body = body


class RawResponse:
    def __init__(self):
        self.status_code = 0
        self.headers = {}
        self.body = ""

    def set_header(self, name, value):
        self.headers[name.lower()] = value

    def end(self, body):
        self.body = body


def test_raw_host_boundary_requires_verifier_and_enforces_body_limit():
    core = FakeCore()
    exposure = create_gateway_exposure("host-route", core=core, host_version="1.0.0", host_api=TEST_HOST_API)
    route = next(item for item in exposure.routes if item.path == "/open-android-intelligence/v2/events")
    response = RawResponse()
    route.handler(RawRequest(url="/open-android-intelligence/v2/events"), response)
    assert response.status_code == 401
    assert core.requests == []

    verifier_calls = []
    exposure = create_gateway_exposure(
        "host-route", core=core, host_version="1.0.0", host_api=TEST_HOST_API, max_body_bytes=1,
        verify_request=lambda request: verifier_calls.append(request) or _verified(),
    )
    route = next(item for item in exposure.routes if item.path == "/open-android-intelligence/v2/negotiate")
    response = RawResponse()
    route.handler(RawRequest(), response)
    assert response.status_code == 413
    assert verifier_calls == []


def test_raw_host_boundary_passes_exact_bytes_to_verifier_before_core():
    core = FakeCore()
    seen = []

    def verifier(request):
        seen.append(request)
        return _verified(request["target"])

    exposure = create_gateway_exposure("direct-tls", core=core, host_version="1.0.0", host_api=TEST_HOST_API, verify_request=verifier)
    route = next(item for item in exposure.routes if item.path == "/open-android-intelligence/v2/conversations")
    response = RawResponse()
    route.handler(RawRequest(b"{}", url="/open-android-intelligence/v2/conversations"), response)
    assert response.status_code == 200
    assert seen[0]["body"] == b"{}"
    assert core.requests[0].target == "/open-android-intelligence/v2/conversations"


def test_verified_exposure_seam_reaches_the_independent_python_core(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    request = make_verified_request({
        "context": {
            "accountId": "account-a", "deviceId": "device-a", "sessionId": "session-a",
            "requestId": "request-a", "correlationId": "correlation-a",
            "pairingGeneration": 1, "grantRevision": 1,
        },
        "method": "POST", "target": "/open-android-intelligence/v2/conversations",
        "body": {"clientConversationId": "conv_exposure"},
        "idempotencyKey": "request-a",
    })
    exposure = create_gateway_exposure("loopback-reverse-proxy", core=core, host_version="1.0.0", host_api=TEST_HOST_API)
    route = next(item for item in exposure.routes if item.path == "/open-android-intelligence/v2/conversations")

    response = route.handle({"verifiedRequest": request})

    assert response["statusCode"] == 200
    assert response["body"]["data"]["conversation"]["clientConversationId"] == "conv_exposure"


def test_negotiate_raw_route_has_independent_pre_auth_input_without_verifier(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    body = {
        "negotiationId": "neg_raw",
        "protocol": {"major": 2, "minor": 1},
        "client": {"installationId": "install_raw", "appVersion": "2.0.0", "platform": "android", "platformApi": 35},
        "features": {
            "auth": ["password"], "messages": ["chat-v1"], "attachments": ["staged-sha256-v1"],
            "events": ["sse-cursor-v1"], "deviceRequests": ["risk-queue-v1"],
        },
        "schemaHashes": {"core": core_schema_hash()},
    }

    exposure = create_gateway_exposure(
        "host-route", core=core, host_version="1.0.0",
        host_api=HostApiCompatibility("1.0.0", "1.0.0", "0123456789abcdef0123456789abcdef01234567"),
    )
    route = next(item for item in exposure.routes if item.path == "/open-android-intelligence/v2/negotiate")
    request = RawRequest(json.dumps(body).encode("utf-8"))
    response = RawResponse()

    route.handler(request, response)

    assert response.status_code == 200
    assert json.loads(response.body)["data"]["protocol"] == {"major": 2, "minor": 1}


def _gateway_routes_for_session_test(tmp_path):
    core = create_gateway_core(
        storage_root=tmp_path,
        credential_verifier=PasswordVerifierDouble(),
    )
    account = core.open_gateway_account("alice")
    account.close()
    exposure = create_gateway_exposure(
        "host-route",
        core=core,
        host_version="1.0.0",
        host_api=TEST_HOST_API,
    )
    return core, {route.path: route for route in exposure.routes}


def _negotiate_for_session(routes, negotiation_id, installation_id):
    response = routes["/open-android-intelligence/v2/negotiate"].handle({
        "method": "POST",
        "target": "/open-android-intelligence/v2/negotiate",
        "body": {
            "negotiationId": negotiation_id,
            "protocol": {"major": 2, "minor": 1},
            "client": {
                "installationId": installation_id,
                "appVersion": "2.0.0",
                "platform": "android",
                "platformApi": 35,
            },
            "features": {
                "auth": ["password", "refresh"],
                "messages": ["chat-v1"],
                "attachments": ["staged-sha256-v1"],
                "events": ["sse-cursor-v1"],
                "deviceRequests": ["risk-queue-v1"],
            },
            "schemaHashes": {"core": core_schema_hash()},
        },
    })
    assert response["statusCode"] == 200


def _password_login(routes, negotiation_id, installation_id):
    response = routes["/open-android-intelligence/v2/sessions/password"].handle({
        "method": "POST",
        "target": "/open-android-intelligence/v2/sessions/password",
        "body": {
            "negotiationId": negotiation_id,
            "username": "alice",
            "password": "password",
            "installation": {
                "installationId": installation_id,
                "displayName": "Alice test device",
                "devicePublicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            },
        },
    })
    assert response["statusCode"] == 200
    return response["body"]["data"]


def test_unknown_password_login_never_creates_an_account(tmp_path):
    core, routes = _gateway_routes_for_session_test(tmp_path)

    response = routes["/open-android-intelligence/v2/sessions/password"].handle({
        "method": "POST",
        "target": "/open-android-intelligence/v2/sessions/password",
        "body": {
            "negotiationId": "neg-unknown",
            "username": "unknown-e2e",
            "password": "password",
            "installation": {
                "installationId": "install-unknown",
                "displayName": "Unknown",
                "devicePublicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            },
        },
    })

    assert response["statusCode"] == 401
    assert response["body"]["error"]["code"] == "AUTHENTICATION_FAILED"
    assert not core.account_exists("unknown-e2e")


def test_raw_unknown_password_login_never_creates_an_account(tmp_path):
    core, routes = _gateway_routes_for_session_test(tmp_path)
    response = RawResponse()
    route = routes["/open-android-intelligence/v2/sessions/password"]
    route.handler(
        RawRequest(
            json.dumps({
                "negotiationId": "neg-raw-unknown",
                "username": "unknown-e2e-raw",
                "password": "password",
                "installation": {
                    "installationId": "install-unknown-raw",
                    "displayName": "Unknown",
                    "devicePublicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                },
            }).encode("utf-8"),
            url="/open-android-intelligence/v2/sessions/password",
        ),
        response,
    )

    assert response.status_code == 401
    assert json.loads(response.body)["error"]["code"] == "AUTHENTICATION_FAILED"
    assert not core.account_exists("unknown-e2e-raw")


def test_current_head_session_routes_register_device_keys_and_rotate_or_revoke(tmp_path):
    core, routes = _gateway_routes_for_session_test(tmp_path)
    negotiation_id = "neg-session"
    installation_id = "install-session"
    _negotiate_for_session(routes, negotiation_id, installation_id)
    session = _password_login(routes, negotiation_id, installation_id)

    account = core.open_gateway_account("alice")
    try:
        table = account.store.database.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'device_keys'"
        ).fetchone()
        assert table is not None
        device_key = account.store.database.execute(
            "SELECT public_key FROM device_keys WHERE device_id = ?",
            (session["deviceId"],),
        ).fetchone()
        assert device_key[0] == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    finally:
        account.close()

    refresh = routes["/open-android-intelligence/v2/sessions/refresh"].handle({
        "method": "POST",
        "target": "/open-android-intelligence/v2/sessions/refresh",
        "body": {
            "negotiationId": negotiation_id,
            "accountId": "alice",
            "installationId": installation_id,
            "deviceId": session["deviceId"],
            "refreshCredential": session["refreshCredential"],
        },
    })
    assert refresh["statusCode"] == 200
    assert refresh["body"]["data"]["deviceId"] == session["deviceId"]
    rotated = refresh["body"]["data"]

    logout = routes["/open-android-intelligence/v2/sessions/current"].handle({
        "method": "DELETE",
        "target": "/open-android-intelligence/v2/sessions/current?revokeRefresh=false",
        "headers": {
            "authorization": "Bearer " + rotated["accessToken"],
            "x-open-android-intelligence-account": "alice",
            "x-open-android-intelligence-device": rotated["deviceId"],
            "x-open-android-intelligence-session": rotated["sessionId"],
        },
    })
    assert logout["statusCode"] == 200
    assert logout["body"]["data"]["refreshRevoked"] is False

    account = core.open_gateway_account("alice")
    try:
        assert account.sessions.active_refresh_credential_count(rotated["deviceId"]) == 1
    finally:
        account.close()

    negotiation_id_2 = "neg-session-2"
    _negotiate_for_session(routes, negotiation_id_2, installation_id)
    session_2 = _password_login(routes, negotiation_id_2, installation_id)
    logout = routes["/open-android-intelligence/v2/sessions/current"].handle({
        "method": "DELETE",
        "target": "/open-android-intelligence/v2/sessions/current?revokeRefresh=true",
        "headers": {
            "authorization": "Bearer " + session_2["accessToken"],
            "x-open-android-intelligence-account": "alice",
            "x-open-android-intelligence-device": session_2["deviceId"],
            "x-open-android-intelligence-session": session_2["sessionId"],
        },
    })
    assert logout["statusCode"] == 200
    assert logout["body"]["data"]["refreshRevoked"] is True

    # Contract §13 (`:796`): logging out revokes the refresh credential and does
    # NOT delete the pairing. `device_keys` has to survive here — deleting it is
    # unpairing (`:798`), which is `DELETE /pairings/current`, not this route.
    account = core.open_gateway_account("alice")
    try:
        assert account.sessions.active_refresh_credential_count(session_2["deviceId"]) == 0
        assert account.store.database.execute(
            "SELECT public_key FROM device_keys WHERE device_id = ?",
            (session_2["deviceId"],),
        ).fetchone()[0] == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    finally:
        account.close()
