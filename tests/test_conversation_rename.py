"""Conversation rename over the shipped signed-request boundary.

The Android client renames a thread with
`PATCH /open-android-intelligence/v2/conversations/{conversationId}` and the body
`{"title": "..."}` (contract section 7). This suite drives the same seam the
deployed adapter uses — the HTTP boundary, the nine singleton headers, the
Ed25519 signature and the fan-out to Core — so a signed method set that silently
drops `PATCH` fails here instead of showing up as a rename that never persists.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from open_android_intelligence_gateway.adapter import create_gateway_request_verifier
from open_android_intelligence_gateway.admin import HostApiCompatibility, create_admin_service
from open_android_intelligence_gateway.core import (
    GatewayError,
    VerifiedGatewayRequest,
    create_gateway_core,
    request_signature_preimage,
    request_signature_preimage_from_digest,
)
from open_android_intelligence_gateway.http import create_gateway_exposure
from test_support import PasswordVerifierDouble, make_secret_store

ACCOUNT_ID = "alice"
INSTALLATION_ID = "install_rename"
CONVERSATION_PATH = "/open-android-intelligence/v2/conversations"
HOST_API = HostApiCompatibility("1.0.0", "1.0.0", "0123456789abcdef0123456789abcdef01234567")


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _timestamp_millis() -> str:
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def _signed_rename(
    bundle: dict,
    conversation_id: str,
    title: str,
    key: Ed25519PrivateKey,
    *,
    method: str = "PATCH",
    request_id: str = "req_rename_1",
    signed_title: str | None = None,
) -> tuple[str, bytes, dict[str, str]]:
    """One wire request exactly as the phone builds it.

    `signed_title` is a tamper knob: it signs a preimage for a body the request
    does not carry, which the Gateway must reject.
    """
    target = f"{CONVERSATION_PATH}/{conversation_id}"
    body = json.dumps({"title": title}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    signed_body = (
        body
        if signed_title is None
        else json.dumps({"title": signed_title}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    )
    timestamp = _timestamp_millis()
    nonce = _b64url(b"\x01" * 16)
    preimage = request_signature_preimage({
        "method": method,
        "target": target,
        "accountId": ACCOUNT_ID,
        "deviceId": bundle["deviceId"],
        "sessionId": bundle["sessionId"],
        "requestId": request_id,
        "timestamp": timestamp,
        "nonce": nonce,
        "bodyHex": signed_body.hex(),
    })
    headers = {
        "Authorization": f"Bearer {bundle['accessToken']}",
        "X-Open-Android-Intelligence-Protocol": "2.1",
        "X-Open-Android-Intelligence-Account": ACCOUNT_ID,
        "X-Open-Android-Intelligence-Device": bundle["deviceId"],
        "X-Open-Android-Intelligence-Session": bundle["sessionId"],
        "X-Open-Android-Intelligence-Request-Id": request_id,
        "X-Open-Android-Intelligence-Timestamp": timestamp,
        "X-Open-Android-Intelligence-Nonce": nonce,
        "X-Open-Android-Intelligence-Signature": _b64url(key.sign(preimage)),
        "Idempotency-Key": request_id,
        "Content-Type": "application/json",
    }
    return target, body, headers


def _gateway(tmp_path, key: Ed25519PrivateKey):
    core = create_gateway_core(tmp_path, secret_store=make_secret_store())
    core.credential_verifier = PasswordVerifierDouble()
    admin = create_admin_service(core=core, host_version="1.0.0", host_api=HOST_API)
    created = admin.create_account(
        {"accountId": ACCOUNT_ID, "password": "password", "localConfirmation": True}
    )
    assert created.get("ok", created.get("success", False)), created
    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        bundle = account.sessions.create_password_session(
            username=ACCOUNT_ID,
            password="password",
            installation={
                "installationId": INSTALLATION_ID,
                "displayName": "Rename test device",
                "devicePublicKey": _b64url(key.public_key().public_bytes_raw()),
            },
            correlation_id="cor_session",
        )
        conversation = account.conversations.create("cconv_rename", "原标题", "cor_create")
    finally:
        account.close()
    exposure = create_gateway_exposure(
        "host-route",
        core=core,
        host_version="1.0.0",
        host_api=HOST_API,
        verify_request=create_gateway_request_verifier(core),
    )
    return core, bundle, conversation["conversationId"], exposure


def _stored_title(core, conversation_id: str) -> str | None:
    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        return account.conversations.get(conversation_id)["title"]
    finally:
        account.close()


def test_signed_patch_rename_verifies_and_persists(tmp_path):
    key = Ed25519PrivateKey.generate()
    core, bundle, conversation_id, _ = _gateway(tmp_path, key)
    target, body, headers = _signed_rename(bundle, conversation_id, "量子计算与经典物理的核心区别", key)

    verified = create_gateway_request_verifier(core)({
        "method": "PATCH",
        "target": target,
        "headers": headers,
        "body": body,
    })

    assert isinstance(verified, VerifiedGatewayRequest)
    assert verified.method == "PATCH"
    response = core.handle(verified)
    assert response["data"]["conversation"]["title"] == "量子计算与经典物理的核心区别"
    assert _stored_title(core, conversation_id) == "量子计算与经典物理的核心区别"

    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        events = account.events.read_after(None)
    finally:
        account.close()
    title_events = [event for event in events if event["eventType"] == "conversation.title.updated"]
    assert len(title_events) == 1
    assert title_events[0]["payload"]["newTitle"] == "量子计算与经典物理的核心区别"


def test_signed_patch_rename_passes_the_http_boundary(tmp_path):
    key = Ed25519PrivateKey.generate()
    core, bundle, conversation_id, exposure = _gateway(tmp_path, key)
    target, body, headers = _signed_rename(bundle, conversation_id, "重命名走真实 HTTP 边界", key)
    route = next(route for route in exposure.routes if target.startswith(route.path))

    result = route._handle_raw({
        "method": "PATCH",
        "url": target,
        "target": target,
        "headers": headers,
        "rawHeaders": tuple(headers.items()),
        "body": body,
    })

    assert result["statusCode"] == 200, result
    assert result["body"]["data"]["conversation"]["title"] == "重命名走真实 HTTP 边界"
    assert _stored_title(core, conversation_id) == "重命名走真实 HTTP 边界"


def test_tampered_rename_body_fails_closed(tmp_path):
    key = Ed25519PrivateKey.generate()
    core, bundle, conversation_id, _ = _gateway(tmp_path, key)
    target, body, headers = _signed_rename(
        bundle, conversation_id, "被篡改的标题", key, signed_title="签名时的标题"
    )

    verified = create_gateway_request_verifier(core)({
        "method": "PATCH",
        "target": target,
        "headers": headers,
        "body": body,
    })

    assert verified is None
    assert _stored_title(core, conversation_id) == "原标题"


def test_signed_method_set_stays_closed_beyond_patch():
    with pytest.raises(GatewayError) as error:
        request_signature_preimage({
            "method": "OPTIONS",
            "target": CONVERSATION_PATH,
            "accountId": ACCOUNT_ID,
            "deviceId": "dev_1",
            "sessionId": "sess_1",
            "requestId": "req_options",
            "timestamp": "2026-09-19T00:00:00.000Z",
            "nonce": "AAAAAAAAAAAAAAAAAAAAAA",
            "bodyHex": "",
        })
    assert error.value.code == "SCHEMA_INVALID"


def test_streamed_body_digest_builds_the_unchanged_v2_signature_preimage():
    body = b"\x00large\xff-body\x80"
    fields = {
        "method": "PUT",
        "target": "/open-android-intelligence/v2/attachments/att_1/content",
        "accountId": "alice",
        "deviceId": "dev_1",
        "sessionId": "sess_1",
        "requestId": "req_stream_body",
        "timestamp": "2026-09-23T00:00:00.000Z",
        "nonce": _b64url(b"n" * 16),
    }

    from_bytes = request_signature_preimage({**fields, "bodyHex": body.hex()})
    from_digest = request_signature_preimage_from_digest(
        fields, hashlib.sha256(body).hexdigest(),
    )

    assert from_digest == from_bytes


def test_streaming_request_authenticates_digest_before_body_is_available(tmp_path):
    key = Ed25519PrivateKey.generate()
    core, bundle, _conversation_id, _exposure = _gateway(tmp_path, key)
    body = b"streamed binary payload"
    digest = hashlib.sha256(body).digest()
    target = "/open-android-intelligence/v2/attachments/att_signed/content"
    timestamp = _timestamp_millis()
    nonce = _b64url(b"s" * 16)
    request_id = "req_signed_stream"
    preimage = request_signature_preimage({
        "method": "PUT",
        "target": target,
        "accountId": ACCOUNT_ID,
        "deviceId": bundle["deviceId"],
        "sessionId": bundle["sessionId"],
        "requestId": request_id,
        "timestamp": timestamp,
        "nonce": nonce,
        "bodyHex": body.hex(),
    })
    headers = {
        "Authorization": f"Bearer {bundle['accessToken']}",
        "X-Open-Android-Intelligence-Protocol": "2.1",
        "X-Open-Android-Intelligence-Account": ACCOUNT_ID,
        "X-Open-Android-Intelligence-Device": bundle["deviceId"],
        "X-Open-Android-Intelligence-Session": bundle["sessionId"],
        "X-Open-Android-Intelligence-Request-Id": request_id,
        "X-Open-Android-Intelligence-Timestamp": timestamp,
        "X-Open-Android-Intelligence-Nonce": nonce,
        "X-Open-Android-Intelligence-Signature": _b64url(key.sign(preimage)),
        "Idempotency-Key": request_id,
        "Content-Length": str(len(body)),
        "Digest": f"sha-256={base64.b64encode(digest).decode('ascii')}",
        "Content-Type": "image/png",
    }
    verifier = create_gateway_request_verifier(core)

    ticket = verifier.verify_streaming_headers({
        "method": "PUT",
        "target": target,
        "headers": headers,
        "rawHeaders": tuple(headers.items()),
        "body": None,
    })

    assert ticket is not None
    assert ticket.content_length == len(body)
    assert ticket.body_sha256 == digest.hex()
    verified = ticket.complete(SimpleNamespace(size_bytes=len(body), sha256=digest.hex()))
    assert isinstance(verified, VerifiedGatewayRequest)
    assert verified.target == target
