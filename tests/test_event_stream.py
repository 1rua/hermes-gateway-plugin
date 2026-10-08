"""Contract section 9 event stream: verified handshake, cursor authority, framing."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from open_android_intelligence_gateway.adapter import (
    EVENT_STREAM_PATH,
    SSE_HEARTBEAT,
    _sse_frame,
)
from open_android_intelligence_gateway.admin import HostApiCompatibility
from open_android_intelligence_gateway.core import create_gateway_core
from open_android_intelligence_gateway.http import create_gateway_exposure
from test_support import make_secret_store, make_verified_request, trust_core


TEST_HOST_API = HostApiCompatibility(
    "1.0.0", "1.0.0", "0123456789abcdef0123456789abcdef01234567"
)

_real_create_gateway_core = create_gateway_core


def create_gateway_core(storage_root=None, **options):
    options.setdefault("secret_store", make_secret_store())
    return trust_core(_real_create_gateway_core(storage_root=storage_root, **options))


def _route(core, verifier):
    exposure = create_gateway_exposure(
        "host-route", core=core, host_version="1.0.0",
        host_api=TEST_HOST_API, verify_request=verifier,
    )
    return next(item for item in exposure.routes if item.path == EVENT_STREAM_PATH)


def _raw(target):
    return {
        "method": "GET",
        "url": target,
        "target": target,
        "headers": {"accept": "text/event-stream"},
        "rawHeaders": (),
        "body": b"",
    }


def _verified(target, now=None):
    return make_verified_request({
        "context": {
            "accountId": "acct_alice",
            "deviceId": "dev_1",
            "sessionId": "sess_1",
            "requestId": "req_events",
            "correlationId": "cor_events",
            "pairingGeneration": 1,
            "grantRevision": 1,
        },
        "method": "GET",
        "target": target,
        "now": now,
    })


def _append_notice(core, occurred_at):
    account = core.open_gateway_account("acct_alice")
    try:
        return account.events.append(
            "gateway.notice", "cor_notice", {"noticeCode": "maintenance"}, occurred_at,
        )
    finally:
        account.close()


def test_stream_without_a_verifier_is_refused_before_any_event_is_read(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    _append_notice(core, "2026-09-13T00:00:00.000Z")
    route = _route(core, None)

    response = route.event_backlog(_raw(EVENT_STREAM_PATH))

    assert response["statusCode"] == 401
    assert response["body"]["error"]["code"] == "AUTHENTICATION_REQUIRED"
    assert "events" not in response


def test_handshake_returns_the_verified_account_and_its_backlog(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    notice = _append_notice(core, "2026-09-13T00:00:00.000Z")
    seen = []
    route = _route(
        core,
        lambda request: seen.append(request) or _verified(
            EVENT_STREAM_PATH, now="2026-09-13T00:00:00.000Z"
        ),
    )

    response = route.event_backlog(_raw(EVENT_STREAM_PATH))

    assert seen, "the handshake must go through the verification seam"
    assert response["statusCode"] == 200
    assert response["accountId"] == "acct_alice"
    assert [event["eventId"] for event in response["events"]] == [notice["eventId"]]


def test_an_expired_cursor_reports_the_resources_to_rebuild(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    expired = _append_notice(core, "2026-09-10T00:00:00.000Z")
    target = f"{EVENT_STREAM_PATH}?cursor={expired['eventId']}"
    route = _route(core, lambda request: _verified(target, now="2026-09-13T00:00:00.000Z"))

    response = route.event_backlog(_raw(target))

    assert response["statusCode"] == 410
    error = response["body"]["error"]
    assert error["code"] == "CURSOR_EXPIRED"
    assert error["details"]["recoverableResources"] == [
        "conversations", "attachments", "device-requests",
    ]


def test_last_event_id_must_equal_the_query_cursor(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    notice = _append_notice(core, "2026-09-13T00:00:00.000Z")
    target = f"{EVENT_STREAM_PATH}?cursor={notice['eventId']}"
    verified = make_verified_request({
        "context": {
            "accountId": "acct_alice", "deviceId": "dev_1", "sessionId": "sess_1",
            "requestId": "req_events", "correlationId": "cor_events",
            "pairingGeneration": 1, "grantRevision": 1,
        },
        "method": "GET",
        "target": target,
        "lastEventId": "evt_something_else",
        "now": "2026-09-13T00:00:00.000Z",
    })
    route = _route(core, lambda request: verified)

    response = route.event_backlog(_raw(target))

    assert response["statusCode"] == 409
    assert response["body"]["error"]["code"] == "CURSOR_CONFLICT"


def test_frames_carry_the_id_event_and_data_lines_the_contract_defines():
    frame = _sse_frame({
        "eventId": "evt_01",
        "eventType": "conversation.message.completed",
        "correlationId": "cor_01",
        "occurredAt": "2026-09-13T00:00:00.000Z",
        "payload": {"messageId": "msg_01", "text": "hello"},
    }).decode("utf-8")

    assert frame.startswith(
        "id: evt_01\nevent: conversation.message.completed\ndata: "
    )
    assert frame.endswith("\n\n")

    data = json.loads(frame.split("data: ", 1)[1])
    # The `event:` line carries the type; the data object is exactly the three
    # fields the phone's decoder reads.
    assert set(data) == {"correlationId", "occurredAt", "payload"}
    assert data["payload"]["messageId"] == "msg_01"


def test_heartbeat_is_a_comment_and_cannot_move_a_cursor():
    assert SSE_HEARTBEAT == b": ping\n\n"
    assert b"id:" not in SSE_HEARTBEAT
