"""The real Hermes HTTP endpoint streams large attachment bodies into AEAD staging."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

aiohttp = pytest.importorskip("aiohttp")

from open_android_intelligence_gateway.adapter import OpenAndroidPlatformAdapter
from open_android_intelligence_gateway.admin import create_admin_service
from open_android_intelligence_gateway.plugin import GatewayServices
from test_conversation_rename import (
    ACCOUNT_ID,
    HOST_API,
    _b64url,
    _gateway,
    _timestamp_millis,
)
from open_android_intelligence_gateway.core import request_signature_preimage
from open_android_intelligence_gateway.core import request_signature_preimage_from_digest


class _Config:
    def __init__(self):
        self.extra = {"host": "127.0.0.1", "port": 0, "account_id": ACCOUNT_ID}


def _signed_put(
    bundle, attachment_id: str, body: bytes | None, key: Ed25519PrivateKey,
    request_id: str, *, content_length: int | None = None, body_digest: bytes | None = None,
):
    target = f"/open-android-intelligence/v2/attachments/{attachment_id}/content"
    timestamp = _timestamp_millis()
    nonce = _b64url(hashlib.sha256(request_id.encode("ascii")).digest()[:16])
    if body is not None:
        content_length = len(body)
        body_digest = hashlib.sha256(body).digest()
    assert content_length is not None and body_digest is not None
    fields = {
        "method": "PUT",
        "target": target,
        "accountId": ACCOUNT_ID,
        "deviceId": bundle["deviceId"],
        "sessionId": bundle["sessionId"],
        "requestId": request_id,
        "timestamp": timestamp,
        "nonce": nonce,
    }
    preimage = request_signature_preimage_from_digest(fields, body_digest.hex())
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
        "Content-Type": "image/png",
        "Content-Length": str(content_length),
        "Digest": f"sha-256={base64.b64encode(body_digest).decode('ascii')}",
    }
    return target, headers


def _signed_empty_request(bundle, target: str, method: str, key: Ed25519PrivateKey, request_id: str):
    timestamp = _timestamp_millis()
    nonce = _b64url(hashlib.sha256(request_id.encode("ascii")).digest()[:16])
    preimage = request_signature_preimage({
        "method": method,
        "target": target,
        "accountId": ACCOUNT_ID,
        "deviceId": bundle["deviceId"],
        "sessionId": bundle["sessionId"],
        "requestId": request_id,
        "timestamp": timestamp,
        "nonce": nonce,
        "bodyHex": "",
    })
    return {
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
        "Content-Length": "0",
    }


def _repeated_image_chunk() -> bytes:
    return b"\x89PNG\r\n\x1a\n" + b"x" * (64 * 1024 - 8)


def _repeat_digest(chunk: bytes, count: int) -> bytes:
    digest = hashlib.sha256()
    for _ in range(count):
        digest.update(chunk)
    return digest.digest()


async def _repeat_chunks(chunk: bytes, count: int, *, corrupt_last: bool = False):
    for index in range(count):
        if corrupt_last and index == count - 1:
            yield chunk[:-1] + b"y"
        else:
            yield chunk


async def _single_chunk(chunk: bytes, started: asyncio.Event):
    started.set()
    yield chunk


async def _blocked_after_one_chunk(chunk: bytes, started: asyncio.Event, release: asyncio.Event):
    yield chunk
    started.set()
    await release.wait()


def test_raw_put_streams_50_mib_image_through_verified_hermes_media_and_rejects_bad_digest(tmp_path):
    async def scenario():
        key = Ed25519PrivateKey.generate()
        core, bundle, _conversation_id, exposure = _gateway(tmp_path, key)
        admin = create_admin_service(core=core, host_version="1.0.0", host_api=HOST_API)
        adapter = OpenAndroidPlatformAdapter(
            _Config(), GatewayServices(core, admin, exposure),
        )
        assert await adapter.connect() is True
        try:
            chunk = _repeated_image_chunk()
            chunk_count = 50 * 1024 * 1024 // len(chunk)
            content_length = chunk_count * len(chunk)
            body_digest = _repeat_digest(chunk, chunk_count)
            account = core.open_gateway_account(ACCOUNT_ID)
            try:
                attachment = account.attachments.create(
                    clientAttachmentId="att_http_stream",
                    filename="large.png",
                    mediaType="image/png",
                    sizeBytes=content_length,
                    sha256=body_digest.hex(),
                    correlationId="cor_http_stream",
                )
            finally:
                account.close()
            target, headers = _signed_put(
                bundle, attachment["attachmentId"], None, key, "req_http_stream",
                content_length=content_length, body_digest=body_digest,
            )

            async with aiohttp.ClientSession() as session:
                async with session.put(
                    f"http://127.0.0.1:{adapter._site._server.sockets[0].getsockname()[1]}{target}",
                    data=_repeat_chunks(chunk, chunk_count),
                    headers=headers,
                ) as response:
                    # The server has finished and moved the complete AEAD spool,
                    # while this client deliberately discards the reply body.
                    assert response.status == 200
                    response.close()

                status_target = f"/open-android-intelligence/v2/attachments/{attachment['attachmentId']}"
                async with session.get(
                    f"http://127.0.0.1:{adapter._site._server.sockets[0].getsockname()[1]}{status_target}",
                    headers=_signed_empty_request(bundle, status_target, "GET", key, "req_http_status_after_lost_put"),
                ) as response:
                    status_body = await response.json()
                assert response.status == 200
                assert status_body["data"]["attachment"] == {
                    "attachmentId": attachment["attachmentId"],
                    "status": "staged",
                    "sizeBytes": content_length,
                    "sha256": body_digest.hex(),
                }

                retry_target, retry_headers = _signed_put(
                    bundle, attachment["attachmentId"], None, key, "req_http_stream_retry",
                    content_length=content_length, body_digest=body_digest,
                )
                async with session.put(
                    f"http://127.0.0.1:{adapter._site._server.sockets[0].getsockname()[1]}{retry_target}",
                    data=_repeat_chunks(chunk, chunk_count),
                    headers=retry_headers,
                ) as response:
                    retry_body = await response.json()
                assert response.status == 200, retry_body
                assert retry_body["data"]["attachment"]["status"] == "staged"

                commit_target = f"/open-android-intelligence/v2/attachments/{attachment['attachmentId']}/commit"
                async with session.post(
                    f"http://127.0.0.1:{adapter._site._server.sockets[0].getsockname()[1]}{commit_target}",
                    data=b"",
                    headers=_signed_empty_request(bundle, commit_target, "POST", key, "req_http_stream_commit"),
                ) as response:
                    commit_body = await response.json()
                assert response.status == 200, commit_body
                assert commit_body["data"]["attachment"]["status"] == "uploaded"

            account = core.open_gateway_account(ACCOUNT_ID)
            try:
                verified = account.attachments.get(attachment["attachmentId"])
                chunks = account.attachments.open_verified_stream(attachment["attachmentId"])
                actual_digest = hashlib.sha256()
                total = 0
                for chunk in chunks:
                    actual_digest.update(chunk)
                    total += len(chunk)
                assert verified["status"] == "uploaded"
                assert total == content_length
                assert actual_digest.digest() == body_digest
            finally:
                account.close()

            # The actual inbound consumer receives ordered host-native local
            # media paths and MIME types. It reads the decrypted stream to EOF
            # before the Gateway ACK removes its encrypted copy.
            message_id = "msg_http_image"
            account = core.open_gateway_account(ACCOUNT_ID)
            try:
                conversation = account.conversations.create(
                    "cconv_http_image", None, "cor_http_image",
                )
                accepted = account.conversations.accept_message(
                    conversation["conversationId"], "client_http_image", "",
                    [attachment["attachmentId"]], bundle["deviceId"],
                    "req_http_image", "cor_http_image",
                )
                dispatch = account.conversations.dispatch_message("client_http_image")
                assert accepted["status"] == "accepted"
                assert dispatch is not None and dispatch["status"] == "queued"
            finally:
                account.close()
            captured = []
            async def capture(event):
                captured.append(event)
            adapter.set_message_handler(capture)
            await adapter._notify_agent_inbound(
                f"/open-android-intelligence/v2/conversations/{conversation['conversationId']}/messages",
                json.dumps({"clientMessageId": "client_http_image", "text": ""}).encode("utf-8"),
                {}, ACCOUNT_ID,
            )
            assert len(captured) == 1
            event = captured[0]
            assert event.text == ""
            assert event.media_types == ["image/png"]
            assert len(event.media_urls) == 1
            media_path = Path(event.media_urls[0])
            assert media_path.is_file()
            cached_digest = hashlib.sha256()
            cached_size = 0
            with media_path.open("rb") as handle:
                while block := handle.read(128 * 1024):
                    cached_digest.update(block)
                    cached_size += len(block)
            assert cached_size == content_length
            assert cached_digest.digest() == body_digest
            account = core.open_gateway_account(ACCOUNT_ID)
            try:
                assert account.attachments.get(attachment["attachmentId"])["status"] == "uploaded"
                dispatch_events = [
                    event for event in account.events.read_after(None)
                    if event["eventType"] == "conversation.message.status"
                    and event["payload"]["clientMessageId"] == "client_http_image"
                ]
                assert [event["payload"]["status"] for event in dispatch_events] == ["queued", "delivered"]
                assert [event["payload"]["revision"] for event in dispatch_events] == [0, 1]
            finally:
                account.close()
            adapter.on_processing_complete(event, "success")
            assert not media_path.exists()
            account = core.open_gateway_account(ACCOUNT_ID)
            try:
                dispatch_events = [
                    event for event in account.events.read_after(None)
                    if event["eventType"] == "conversation.message.status"
                    and event["payload"]["clientMessageId"] == "client_http_image"
                ]
                assert [event["payload"]["status"] for event in dispatch_events] == ["queued", "delivered", "completed"]
                assert [event["payload"]["revision"] for event in dispatch_events] == [0, 1, 2]
                assert [event["payload"]["errorCode"] for event in dispatch_events] == [None, None, None]
            finally:
                account.close()

            expected = b"\x89PNG\r\n\x1a\n" + b"e" * (512 * 1024 + 3)
            corrupted = expected[:-1] + b"f"
            account = core.open_gateway_account(ACCOUNT_ID)
            try:
                bad_attachment = account.attachments.create(
                    clientAttachmentId="att_http_digest_mismatch",
                    filename="bad.png",
                    mediaType="image/png",
                    sizeBytes=len(expected),
                    sha256=hashlib.sha256(expected).hexdigest(),
                    correlationId="cor_http_digest_mismatch",
                )
            finally:
                account.close()
            bad_target, bad_headers = _signed_put(
                bundle, bad_attachment["attachmentId"], expected, key, "req_http_bad_digest",
            )
            bad_headers["Digest"] = f"sha-256={base64.b64encode(hashlib.sha256(expected).digest()).decode('ascii')}"

            async with aiohttp.ClientSession() as session:
                async with session.put(
                    f"http://127.0.0.1:{adapter._site._server.sockets[0].getsockname()[1]}{bad_target}",
                    data=corrupted,
                    headers=bad_headers,
                ) as response:
                    bad_body = await response.json()

            assert response.status == 400
            assert bad_body["error"]["code"] == "ATTACHMENT_DIGEST_MISMATCH"
            account = core.open_gateway_account(ACCOUNT_ID)
            try:
                assert account.attachments.get(bad_attachment["attachmentId"])["status"] == "staged"
                assert account.attachments.get_record(bad_attachment["attachmentId"])["hasStagedBytes"] is False
                assert list(account.paths.attachments.glob(f".{bad_attachment['attachmentId']}.*.upload")) == []

                short_length = len(chunk) * 2
                short_digest = _repeat_digest(chunk, 2)
                truncated = account.attachments.create(
                    clientAttachmentId="att_http_truncated",
                    filename="truncated.png",
                    mediaType="image/png",
                    sizeBytes=short_length,
                    sha256=short_digest.hex(),
                    correlationId="cor_http_truncated",
                )
                attachments_dir = account.paths.attachments
            finally:
                account.close()

            truncated_target, truncated_headers = _signed_put(
                bundle, truncated["attachmentId"], None, key, "req_http_truncated",
                content_length=short_length, body_digest=short_digest,
            )
            truncated_started = asyncio.Event()
            truncated_session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=3),
            )
            truncated_request = asyncio.create_task(truncated_session.put(
                f"http://127.0.0.1:{adapter._site._server.sockets[0].getsockname()[1]}{truncated_target}",
                data=_single_chunk(chunk, truncated_started),
                headers=truncated_headers,
            ))
            await asyncio.wait_for(truncated_started.wait(), timeout=5)
            spool_paths = list(attachments_dir.glob(f".{truncated['attachmentId']}.*.upload"))
            for _ in range(100):
                if spool_paths:
                    break
                await asyncio.sleep(0.01)
                spool_paths = list(attachments_dir.glob(f".{truncated['attachmentId']}.*.upload"))
            assert spool_paths, "server must spool truncated request bytes before disconnect"
            await truncated_session.close()
            try:
                await asyncio.wait_for(truncated_request, timeout=4)
            except (asyncio.CancelledError, aiohttp.ClientError, asyncio.TimeoutError):
                truncated_request.cancel()
            await asyncio.sleep(0.1)

            account = core.open_gateway_account(ACCOUNT_ID)
            try:
                assert account.attachments.get(truncated["attachmentId"])["status"] == "staged"
                assert list(attachments_dir.glob(f".{truncated['attachmentId']}.*.upload")) == []

                cancelled = account.attachments.create(
                    clientAttachmentId="att_http_cancelled",
                    filename="cancelled.png",
                    mediaType="image/png",
                    sizeBytes=short_length,
                    sha256=short_digest.hex(),
                    correlationId="cor_http_cancelled",
                )
                cancelled_id = cancelled["attachmentId"]
            finally:
                account.close()

            cancelled_target, cancelled_headers = _signed_put(
                bundle, cancelled_id, None, key, "req_http_cancelled",
                content_length=short_length, body_digest=short_digest,
            )
            started = asyncio.Event()
            release = asyncio.Event()
            session = aiohttp.ClientSession()
            cancelled_request = asyncio.create_task(session.put(
                f"http://127.0.0.1:{adapter._site._server.sockets[0].getsockname()[1]}{cancelled_target}",
                data=_blocked_after_one_chunk(chunk, started, release),
                headers=cancelled_headers,
            ))
            await asyncio.wait_for(started.wait(), timeout=5)
            spool_paths = list(attachments_dir.glob(f".{cancelled_id}.*.upload"))
            for _ in range(100):
                if spool_paths:
                    break
                await asyncio.sleep(0.01)
                spool_paths = list(attachments_dir.glob(f".{cancelled_id}.*.upload"))
            assert spool_paths, "server must have created the encrypted spool before cancellation"
            cancelled_request.cancel()
            try:
                await cancelled_request
            except asyncio.CancelledError:
                pass
            finally:
                release.set()
                await session.close()
            await asyncio.sleep(0.1)
            account = core.open_gateway_account(ACCOUNT_ID)
            try:
                assert account.attachments.get(cancelled_id)["status"] == "staged"
                assert list(attachments_dir.glob(f".{cancelled_id}.*.upload")) == []
            finally:
                account.close()
        finally:
            await adapter.disconnect()

    asyncio.run(scenario())
