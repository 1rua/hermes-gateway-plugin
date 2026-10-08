"""Logout ends a session; unpairing ends a pairing. They are not the same act.

Contract section 13 (`docs/contracts/gateway-protocol-v2.md:796-799`) keeps the
two apart: logging out revokes the refresh credential and leaves the pairing
alone, while unpairing revokes the device key, the refresh credential, the
grants, the queue and the unconfirmed attachments plus every access session of
that device. The tests here pin both seams and the boundary between them.
"""
from __future__ import annotations
from test_support import enqueue_fixture

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from open_android_intelligence_gateway.admin import (  # noqa: E402
    HostApiCompatibility,
    create_admin_service,
    run_admin_command,
)
from open_android_intelligence_gateway.core import create_gateway_core  # noqa: E402
from open_android_intelligence_gateway.http import create_gateway_exposure  # noqa: E402
from test_support import (  # noqa: E402
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
ACCOUNT_ID = "alice"
INSTALLATION_ID = "install_pairing_revocation"
DEVICE_PUBLIC_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
LOGOUT = "/open-android-intelligence/v2/sessions/current"


def _routes(tmp_path):
    core = create_gateway_core(
        storage_root=tmp_path, credential_verifier=PasswordVerifierDouble()
    )
    account = core.open_gateway_account(ACCOUNT_ID)
    account.close()
    exposure = create_gateway_exposure(
        "host-route", core=core, host_version="1.0.0", host_api=TEST_HOST_API
    )
    return core, {route.path: route for route in exposure.routes}


def _negotiate(routes, negotiation_id, installation_id=INSTALLATION_ID):
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


def _login(routes, negotiation_id, installation_id=INSTALLATION_ID):
    response = routes["/open-android-intelligence/v2/sessions/password"].handle({
        "method": "POST",
        "target": "/open-android-intelligence/v2/sessions/password",
        "body": {
            "negotiationId": negotiation_id,
            "username": ACCOUNT_ID,
            "password": "password",
            "installation": {
                "installationId": installation_id,
                "displayName": "Alice test device",
                "devicePublicKey": DEVICE_PUBLIC_KEY,
            },
        },
    })
    assert response["statusCode"] == 200
    return response["body"]["data"]


def _refresh(routes, negotiation_id, session):
    response = routes["/open-android-intelligence/v2/sessions/refresh"].handle({
        "method": "POST",
        "target": "/open-android-intelligence/v2/sessions/refresh",
        "body": {
            "negotiationId": negotiation_id,
            "accountId": ACCOUNT_ID,
            "installationId": INSTALLATION_ID,
            "deviceId": session["deviceId"],
            "refreshCredential": session["refreshCredential"],
        },
    })
    assert response["statusCode"] == 200
    return response["body"]["data"]


def _logout(routes, session, revoke_refresh):
    return routes[LOGOUT].handle({
        "method": "DELETE",
        "target": f"{LOGOUT}?revokeRefresh={'true' if revoke_refresh else 'false'}",
        "headers": {
            "authorization": "Bearer " + session["accessToken"],
            "x-open-android-intelligence-account": ACCOUNT_ID,
            "x-open-android-intelligence-device": session["deviceId"],
            "x-open-android-intelligence-session": session["sessionId"],
        },
    })


def _device_key(account, device_id):
    return account.store.database.execute(
        "SELECT public_key FROM device_keys WHERE device_id = ?", (device_id,)
    ).fetchone()


def test_logout_with_revoke_refresh_keeps_the_device_key_registered(tmp_path):
    """Contract :796 — logging out revokes the credential, not the pairing."""
    core, routes = _routes(tmp_path)
    negotiation_id = "neg_logout_keeps_key"
    _negotiate(routes, negotiation_id)
    session = _login(routes, negotiation_id)

    response = _logout(routes, session, revoke_refresh=True)
    assert response["statusCode"] == 200
    assert response["body"]["data"] == {"sessionId": session["sessionId"], "refreshRevoked": True}

    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        key = _device_key(account, session["deviceId"])
    finally:
        account.close()

    assert key is not None
    assert key["public_key"] == DEVICE_PUBLIC_KEY


def test_logout_with_revoke_refresh_leaves_the_device_key_able_to_authenticate(tmp_path):
    """The surviving pairing still authenticates: logout is not unpairing."""
    core, routes = _routes(tmp_path)
    negotiation_id = "neg_logout_still_authenticates"
    _negotiate(routes, negotiation_id)
    first = _login(routes, negotiation_id)
    second = _refresh(routes, negotiation_id, first)

    response = _logout(routes, first, revoke_refresh=True)
    assert response["statusCode"] == 200

    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        resolved = account.sessions.resolve_session(
            second["accessToken"], second["sessionId"], second["deviceId"]
        )
    finally:
        account.close()

    assert resolved is not None
    assert resolved["devicePublicKey"] == DEVICE_PUBLIC_KEY


def test_logout_with_revoke_refresh_revokes_the_refresh_credential(tmp_path):
    """The half of logout that did work stays working: the credential dies."""
    core, routes = _routes(tmp_path)
    negotiation_id = "neg_logout_revokes_credential"
    _negotiate(routes, negotiation_id)
    session = _login(routes, negotiation_id)

    assert _logout(routes, session, revoke_refresh=True)["statusCode"] == 200

    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        assert account.sessions.active_refresh_credential_count(session["deviceId"]) == 0
        stale = routes["/open-android-intelligence/v2/sessions/refresh"].handle({
            "method": "POST",
            "target": "/open-android-intelligence/v2/sessions/refresh",
            "body": {
                "negotiationId": negotiation_id,
                "accountId": ACCOUNT_ID,
                "installationId": INSTALLATION_ID,
                "deviceId": session["deviceId"],
                "refreshCredential": session["refreshCredential"],
            },
        })
    finally:
        account.close()

    assert stale["statusCode"] == 401
    assert stale["body"]["error"]["code"] == "REFRESH_REUSED"


UNPAIR = "/open-android-intelligence/v2/pairings/current"


def _verified_unpair(session, request_id, correlation_id="cor_unpair"):
    return make_verified_request({
        "context": {
            "accountId": ACCOUNT_ID,
            "deviceId": session["deviceId"],
            "sessionId": session["sessionId"],
            "requestId": request_id,
            "correlationId": correlation_id,
            "pairingGeneration": 1,
            "grantRevision": 1,
        },
        "method": "DELETE",
        "target": UNPAIR,
        "idempotencyKey": request_id,
    })


def _verified_unpair_without_idempotency_key(session, request_id):
    return make_verified_request({
        "context": {
            "accountId": ACCOUNT_ID,
            "deviceId": session["deviceId"],
            "sessionId": session["sessionId"],
            "requestId": request_id,
            "correlationId": "cor_unpair",
            "pairingGeneration": 1,
            "grantRevision": 1,
        },
        "method": "DELETE",
        "target": UNPAIR,
    })


def _unconfirmed_attachment(
    account,
    body=b"staged body",
    device_id="dev_unpair_fixture",
    client_attachment_id="att_unconfirmed",
):
    attachment = account.attachments.create(
        client_attachment_id=client_attachment_id,
        filename="note.txt",
        media_type="text/plain",
        size_bytes=len(body),
        sha256=hashlib.sha256(body).hexdigest(),
        device_id=device_id,
        pairing_generation=1,
        correlation_id="cor_attachment",
    )
    attachment_id = attachment["attachmentId"]
    account.attachments.upload_content(attachment_id, body)
    account.attachments.commit(attachment_id)
    account.attachments.mark_delivered(attachment_id)
    return attachment_id


def test_unpair_revokes_the_five_items_and_every_access_session(tmp_path):
    """Contract :798 plus D1: keys, credential, grants, queue, attachments, sessions."""
    core, routes = _routes(tmp_path)
    negotiation_id = "neg_unpair"
    _negotiate(routes, negotiation_id)
    session = _login(routes, negotiation_id)
    second = _refresh(routes, negotiation_id, session)

    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        attachment_id = _unconfirmed_attachment(account, device_id=session["deviceId"])
        other_device_attachment_id = _unconfirmed_attachment(
            account,
            device_id="dev_other_device",
            client_attachment_id="att_unconfirmed_other_device",
        )
        assert account.attachments.get_record(attachment_id)["hasStagedBytes"] is True
        assert account.attachments.get_record(other_device_attachment_id)["hasStagedBytes"] is True
        enqueue_fixture(account,
            request_id="req_unpair_queue",
            device_id=session["deviceId"],
            pairing_generation=1,
            grant_revision=1,
            risk="read",
            capability={"id": "org.openandroidintelligence.sms.query", "version": "1.0.0"},
            provider={"pluginId": "org.openandroidintelligence.sms", "authorKeyId": "sha256:" + "a" * 64},
            parameters={"query": "from:alice"},
            correlation_id="cor_queue",
        )
    finally:
        account.close()

    response = routes[UNPAIR].handle({"verifiedRequest": _verified_unpair(session, "req_unpair_1")})

    assert response["statusCode"] == 200
    assert set(response["body"]["data"]) == {
        "deviceId", "deviceKeysRevoked", "refreshRevoked", "grantsRevoked",
        "deviceRequestsRevoked", "unconfirmedAttachmentsRevoked", "sessionsRevoked",
    }
    assert response["body"]["data"] == {
        "deviceId": session["deviceId"],
        "deviceKeysRevoked": True,
        "refreshRevoked": True,
        "grantsRevoked": True,
        "deviceRequestsRevoked": True,
        "unconfirmedAttachmentsRevoked": True,
        "sessionsRevoked": True,
    }

    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        # The pairing itself is gone: no key left to sign a request with.
        assert _device_key(account, session["deviceId"]) is None
        assert account.sessions.active_refresh_credential_count(session["deviceId"]) == 0
        live_sessions = account.store.database.execute(
            "SELECT COUNT(*) FROM access_sessions WHERE device_id = ? AND status = 'active'",
            (session["deviceId"],),
        ).fetchone()[0]
        assert live_sessions == 0
        # D1: the generation moved, so every record bound to the old one is fenced.
        generation = account.store.database.execute(
            "SELECT value FROM account_metadata WHERE key = 'pairing_generation'"
        ).fetchone()[0]
        assert generation == "2"
        queue = [item for item in account.device_requests.list()
                 if item["deviceId"] == session["deviceId"]]
        assert [item["state"] for item in queue] == ["cancelled"]
        assert account.attachments.get_record(attachment_id)["hasStagedBytes"] is False
        assert account.attachments.get_record(other_device_attachment_id)["hasStagedBytes"] is True
        assert account._unconfirmed_attachment_count(session["deviceId"], 1) == 0
        assert account._unconfirmed_attachment_count("dev_other_device", 1) == 1
        # Both sessions died, not only the one that asked.
        assert account.sessions.resolve_session(
            second["accessToken"], second["sessionId"], second["deviceId"]
        ) is None
    finally:
        account.close()


def test_unpair_without_an_active_pairing_answers_pairing_required(tmp_path):
    """D1's first error code: there is no pairing here to destroy."""
    core, routes = _routes(tmp_path)
    session = {"deviceId": "dev_unpaired", "sessionId": "sess_unpaired"}

    response = routes[UNPAIR].handle({"verifiedRequest": _verified_unpair(session, "req_unpair_2")})

    assert response["statusCode"] == 400
    assert response["body"]["error"]["code"] == "PAIRING_REQUIRED"

    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        # A device that was never paired leaves the account's generation alone.
        assert account.pairing_generation() == 1
    finally:
        account.close()


def test_unpair_replay_returns_one_terminal_outcome(tmp_path):
    """Contract §12: the same Idempotency-Key answers the state it produced."""
    core, routes = _routes(tmp_path)
    negotiation_id = "neg_unpair_replay"
    _negotiate(routes, negotiation_id)
    session = _login(routes, negotiation_id)

    request = _verified_unpair(session, "req_unpair_3")
    first = routes[UNPAIR].handle({"verifiedRequest": request})
    replay = routes[UNPAIR].handle({"verifiedRequest": request})

    assert first["statusCode"] == 200
    assert replay == first

    # One sweep, not two: the generation moved exactly once.
    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        assert account.pairing_generation() == 2
    finally:
        account.close()


def test_unpair_without_an_idempotency_key_is_refused(tmp_path):
    """D1: destroying a pairing is a signed, idempotency-keyed request."""
    core, routes = _routes(tmp_path)
    negotiation_id = "neg_unpair_no_key"
    _negotiate(routes, negotiation_id)
    session = _login(routes, negotiation_id)

    response = routes[UNPAIR].handle(
        {"verifiedRequest": _verified_unpair_without_idempotency_key(session, "req_unpair_4")}
    )

    assert response["statusCode"] == 409
    assert response["body"]["error"]["code"] == "IDEMPOTENCY_CONFLICT"

    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        assert _device_key(account, session["deviceId"]) is not None
        assert account.pairing_generation() == 1
    finally:
        account.close()


def test_unpair_refuses_a_request_that_never_reached_the_verified_seam(tmp_path):
    """D1: no exemption here — an unverified mapping is not a pairing owner."""
    core, routes = _routes(tmp_path)
    negotiation_id = "neg_unpair_unverified"
    _negotiate(routes, negotiation_id)
    session = _login(routes, negotiation_id)

    plain = {
        "context": {
            "accountId": ACCOUNT_ID,
            "deviceId": session["deviceId"],
            "sessionId": session["sessionId"],
            "requestId": "req_unpair_5",
            "correlationId": "cor_unpair",
            "pairingGeneration": 1,
            "grantRevision": 1,
        },
        "method": "DELETE",
        "target": UNPAIR,
        "idempotencyKey": "req_unpair_5",
    }

    response = routes[UNPAIR].handle({"verifiedRequest": plain})

    assert response["statusCode"] == 401
    assert response["body"]["error"]["code"] == "AUTHENTICATION_REQUIRED"

    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        assert _device_key(account, session["deviceId"]) is not None
        assert account.pairing_generation() == 1
    finally:
        account.close()


def test_admin_pairing_revoke_is_a_sibling_of_account_delete(tmp_path):
    """The host management surface: pairing-level, gated like account.delete."""
    core, routes = _routes(tmp_path)
    negotiation_id = "neg_admin_unpair"
    _negotiate(routes, negotiation_id)
    session = _login(routes, negotiation_id)

    service = create_admin_service(
        core=core, storage_root=tmp_path, host_version="1.0.0", host_api=TEST_HOST_API
    )
    read_only = create_admin_service(
        core=core, storage_root=tmp_path, host_version="2.0.0", host_api=TEST_HOST_API
    )

    assert read_only.pairing_revoke({
        "accountId": ACCOUNT_ID, "deviceId": session["deviceId"], "localConfirmation": True,
    })["error"]["code"] == "HOST_INCOMPATIBLE"
    assert service.pairing_revoke({
        "accountId": ACCOUNT_ID, "deviceId": session["deviceId"],
    })["error"]["code"] == "LOCAL_CONFIRMATION_REQUIRED"

    revoked = service.pairing_revoke({
        "accountId": ACCOUNT_ID, "deviceId": session["deviceId"], "localConfirmation": True,
    })
    assert revoked["ok"] is True
    assert revoked["operation"] == "pairing.revoke"
    assert revoked["data"]["deviceKeysRevoked"] is True

    again = service.pairing_revoke({
        "accountId": ACCOUNT_ID, "deviceId": session["deviceId"], "localConfirmation": True,
    })
    assert again["error"]["code"] == "PAIRING_REQUIRED"

    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        assert _device_key(account, session["deviceId"]) is None
    finally:
        account.close()


class _RawRequest:
    def __init__(self, url, method="DELETE", body=b""):
        self.method = method
        self.url = url
        self.headers = {}
        self.rawHeaders = ()
        self.body = body


class _RawResponse:
    def __init__(self):
        self.status_code = 0
        self.headers = {}
        self.body = ""

    def set_header(self, name, value):
        self.headers[name.lower()] = value

    def end(self, body):
        self.body = body


def test_unpair_reaches_the_core_only_through_the_host_request_verifier(tmp_path):
    """D1's strength split: no pre-auth exemption, so the host must verify."""
    core, routes = _routes(tmp_path)
    negotiation_id = "neg_unpair_raw"
    _negotiate(routes, negotiation_id)
    session = _login(routes, negotiation_id)

    route = next(
        item for item in create_gateway_exposure(
            "host-route", core=core, host_version="1.0.0", host_api=TEST_HOST_API,
        ).routes if item.path == UNPAIR
    )
    untrusted = _RawResponse()
    route.handler(_RawRequest(UNPAIR), untrusted)
    assert untrusted.status_code == 401

    seen = []
    route = next(
        item for item in create_gateway_exposure(
            "host-route", core=core, host_version="1.0.0", host_api=TEST_HOST_API,
            verify_request=lambda request: seen.append(request)
            or _verified_unpair(session, "req_unpair_6"),
        ).routes if item.path == UNPAIR
    )
    trusted = _RawResponse()
    route.handler(_RawRequest(UNPAIR), trusted)

    assert trusted.status_code == 200
    assert json.loads(trusted.body)["data"]["deviceKeysRevoked"] is True
    assert [request["method"] for request in seen] == ["DELETE"]


def test_admin_cli_revokes_a_pairing_only_after_local_confirmation(tmp_path):
    """The local CLI is a confirmed write, exactly like `account delete`."""
    core, routes = _routes(tmp_path)
    negotiation_id = "neg_admin_cli_unpair"
    _negotiate(routes, negotiation_id)
    session = _login(routes, negotiation_id)
    device_id = session["deviceId"]

    service = create_admin_service(
        core=core, storage_root=tmp_path, host_version="1.0.0", host_api=TEST_HOST_API
    )

    assert run_admin_command(
        ["pairing", "revoke", ACCOUNT_ID, device_id], service=service
    )["error"]["code"] == "LOCAL_CONFIRMATION_REQUIRED"
    assert run_admin_command(
        ["pairing", "revoke", ACCOUNT_ID, device_id, "--confirm-local"], service=service
    )["ok"] is True

    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        assert _device_key(account, device_id) is None
    finally:
        account.close()
