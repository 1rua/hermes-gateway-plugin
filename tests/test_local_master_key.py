import hashlib
"""ADR 0023: operator-provided master key file and fail-closed Gateway startup."""

import asyncio
import os
import sqlite3
import subprocess
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from open_android_intelligence_gateway.adapter import OpenAndroidPlatformAdapter
from open_android_intelligence_gateway.admin import HostApiCompatibility
from open_android_intelligence_gateway.plugin import GatewayServices
from open_android_intelligence_gateway.core import (
    VerifiedGatewayRequest,
    VerifiedRequestContext,
    create_gateway_core,
)
from open_android_intelligence_gateway.http import create_gateway_exposure
from open_android_intelligence_gateway.local_keys import (
    MASTER_KEY_FILE_ENV,
    LocalMasterKeyStore,
    MasterKeyUnavailable,
    create_master_key_file,
    master_key_unavailable_reason,
    resolve_local_master_key_store,
)
from test_support import core_schema_hash, make_verified_request

ACCOUNT_ID = "acct_local_key"


def _key_file(tmp_path) -> Path:
    os.chmod(tmp_path, 0o700)
    return create_master_key_file(tmp_path / "gateway-master-key")


def _services(core):
    host_api = HostApiCompatibility("1.0.0", "1.0.0", "0123456789abcdef0123456789abcdef01234567")
    exposure = create_gateway_exposure(
        "host-route", core=core, host_version="1.0.0", host_api=host_api,
    )
    return GatewayServices(core, None, exposure)


class _Config:
    def __init__(self):
        self.extra = {"port": 0, "host": "127.0.0.1", "account_id": ACCOUNT_ID}


def _context():
    return VerifiedRequestContext(
        accountId=ACCOUNT_ID, deviceId="dev_local", sessionId="sess_local",
        requestId="req_local", correlationId="cor_local",
        pairingGeneration=1, grantRevision=1,
    )


def test_missing_key_file_is_refused_with_an_actionable_reason(tmp_path):
    store = LocalMasterKeyStore(tmp_path / "absent")
    with pytest.raises(MasterKeyUnavailable) as error:
        store.validate()
    message = str(error.value)
    assert "init-key" in message and "不存在" in message


def test_group_or_other_readable_key_file_is_refused(tmp_path):
    path = _key_file(tmp_path)
    os.chmod(path, 0o644)
    with pytest.raises(MasterKeyUnavailable) as error:
        LocalMasterKeyStore(path).validate()
    assert "0600" in str(error.value)


def test_symlinked_key_source_is_refused(tmp_path):
    real = _key_file(tmp_path)
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(MasterKeyUnavailable) as error:
        LocalMasterKeyStore(link).validate()
    assert "符号链接" in str(error.value)


def test_provisioning_never_overwrites_an_existing_key(tmp_path):
    path = _key_file(tmp_path)
    with pytest.raises(FileExistsError):
        create_master_key_file(path)


def test_each_account_derives_a_distinct_key_and_round_trips(tmp_path):
    store = LocalMasterKeyStore(_key_file(tmp_path))
    first = store.get_or_create_aead("open-android-intelligence-gateway/acct_a")
    second = store.get_or_create_aead("open-android-intelligence-gateway/acct_b")
    assert first.reference != second.reference
    assert first.algorithm == "AES-256-GCM" and first.authenticated is True
    sealed = first.encrypt(b"\x00\x7b\x7d+%\xff\x80\xc3\xa9", b"staged-attachment")
    assert first.decrypt(sealed, b"staged-attachment") == b"\x00\x7b\x7d+%\xff\x80\xc3\xa9"
    with pytest.raises(Exception):
        second.decrypt(sealed, b"staged-attachment")
    with pytest.raises(Exception):
        first.decrypt(sealed, b"other-purpose")
    with pytest.raises(Exception):
        first.decrypt(sealed[:-1] + bytes([sealed[-1] ^ 1]), b"staged-attachment")


def test_installing_the_plugin_provisions_the_key_without_a_manual_step(tmp_path):
    """The operator installs the plugin and runs hermes gateway setup; nothing else."""
    path = tmp_path / "auto" / "gateway-master-key"
    assert not path.exists()
    resolved = resolve_local_master_key_store({MASTER_KEY_FILE_ENV: str(path)})
    assert path.exists() and resolved.path == path
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    resolved.validate()
    # A second start reuses the same key instead of rotating it under live data.
    again = resolve_local_master_key_store({MASTER_KEY_FILE_ENV: str(path)})
    assert again.get_or_create_aead("acct").reference == resolved.get_or_create_aead("acct").reference


def test_an_unwritable_key_path_is_reported_instead_of_crashing(tmp_path):
    directory = tmp_path / "blocked"
    directory.mkdir()
    os.chmod(directory, 0o500)
    try:
        with pytest.raises(MasterKeyUnavailable) as error:
            resolve_local_master_key_store({MASTER_KEY_FILE_ENV: str(directory / "key")})
        assert "init-key" in str(error.value)
    finally:
        os.chmod(directory, 0o700)


def test_local_key_source_unblocks_authenticated_requests(tmp_path):
    store = LocalMasterKeyStore(_key_file(tmp_path))
    core = create_gateway_core(storage_root=tmp_path / "storage", secret_store=store)
    account = core.open_gateway_account(ACCOUNT_ID)
    assert account.master_key_ref.startswith("local-key-v1:")
    assert account.store.aead is not None

    request = VerifiedGatewayRequest(
        context=_context(), method="GET",
        target="/open-android-intelligence/v2/conversations",
        idempotencyKey=None, lastEventId=None, now="2026-09-15T14:03:30.000Z",
    )
    response = core.handle(request)
    assert "error" not in response
    assert response["data"] == {"conversations": []}

    created = core.handle(VerifiedGatewayRequest(
        context=_context(), method="POST",
        target="/open-android-intelligence/v2/attachments",
        idempotencyKey="req_local",
        body={
            "clientAttachmentId": "att_client_local", "filename": "note.txt",
            "mediaType": "text/plain", "sizeBytes": 5, "sha256": "0" * 64,
        },
        now="2026-09-15T14:03:31.000Z",
    ))
    assert "error" not in created
    assert created["data"]["attachment"]["attachmentId"].startswith("att_")


def test_local_key_source_carries_the_full_attachment_and_message_flow(tmp_path):
    """The exact flow the phone performs: stage bytes, verify, then reference them."""
    import hashlib

    store = LocalMasterKeyStore(_key_file(tmp_path))
    core = create_gateway_core(storage_root=tmp_path / "storage", secret_store=store)
    account = core.open_gateway_account(ACCOUNT_ID)
    body = b"\x00\x7b\x7d+%\xff\x80\xc3\xa9"

    attachment = account.attachments.create(
        client_attachment_id="att_client_local", filename="interop.bin",
        media_type="text/plain", size_bytes=len(body),
        sha256=hashlib.sha256(body).hexdigest(), correlation_id="cor_local",
    )
    attachment_id = attachment["attachmentId"]
    account.attachments.upload_content(attachment_id, body)
    verified = account.attachments.commit(attachment_id)
    assert verified["status"] == "uploaded"

    # Staged bytes are stored sealed, never as plaintext on disk.
    staged = (account.paths.attachments / f"{attachment_id}.stage").read_text()
    assert staged.startswith("OAI-ATTACHMENT-AEAD-STREAM\x02\n") and "interop.bin" not in staged

    conversation = account.conversations.create("cconv_local", None, "cor_local")
    accepted = account.conversations.accept_message(
        conversation["conversationId"], "cmsg_local", "请读取附件", [attachment_id],
        "dev_local", "req_local", "cor_local",
    )
    assert accepted["status"] == "accepted"
    assert accepted["messageId"].startswith("msg_")
    assert accepted["conversationId"] == conversation["conversationId"]


def test_gateway_refuses_to_start_without_any_key_source(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    assert master_key_unavailable_reason(core) is not None

    async def scenario():
        adapter = OpenAndroidPlatformAdapter(_Config(), _services(core))
        started = await adapter.connect()
        await adapter.disconnect()
        return started

    assert asyncio.run(scenario()) is False


def test_gateway_starts_once_the_operator_provides_a_key_file(tmp_path):
    core = create_gateway_core(
        storage_root=tmp_path,
        secret_store=LocalMasterKeyStore(_key_file(tmp_path)),
    )
    assert master_key_unavailable_reason(core) is None

    async def scenario():
        adapter = OpenAndroidPlatformAdapter(_Config(), _services(core))
        started = await adapter.connect()
        await adapter.disconnect()
        return started

    assert asyncio.run(scenario()) is True


def test_account_created_through_the_cli_already_carries_a_master_key(tmp_path):
    """The documented flow: install the plugin, create the account, pair the phone."""
    plugin_root = Path(__file__).resolve().parents[1]
    home = tmp_path / "home"
    storage = tmp_path / "storage"
    home.mkdir()
    completed = subprocess.run(
        [sys.executable, str(plugin_root / "tools" / "hermes-account.py"), "create", "phone1",
         "--password", "TestPass123"],
        cwd=plugin_root,
        env={**os.environ, "HOME": str(home), "HERMES_STORAGE_ROOT": str(storage)},
        capture_output=True, text=True, timeout=120,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "phone1" in completed.stdout

    databases = list(storage.rglob("gateway.sqlite"))
    assert len(databases) == 1
    with sqlite3.connect(f"file:{databases[0]}?mode=ro", uri=True) as connection:
        value = connection.execute(
            "SELECT value FROM account_metadata WHERE key = 'master_key_ref'"
        ).fetchone()[0]
    assert value.startswith("local-key-v1:")

    key_file = home / ".open-android-intelligence" / "gateway-master-key"
    assert key_file.exists()
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600


def test_mobile_media_types_including_heic_and_office_are_accepted(tmp_path):
    store = LocalMasterKeyStore(_key_file(tmp_path))
    core = create_gateway_core(storage_root=tmp_path / "storage", secret_store=store)
    account = core.open_gateway_account(ACCOUNT_ID)

    for mtype in ["image/heic", "image/heif", "image/gif", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/octet-stream"]:
        att = account.attachments.create(
            client_attachment_id="att_" + mtype.replace("/", "_").replace(".", "_"),
            filename="sample_file",
            media_type=mtype,
            size_bytes=16,
            sha256="0" * 64,
            correlation_id="cor_type",
        )
        assert att["attachmentId"].startswith("att_")
        assert account.attachments.get_record(att["attachmentId"])["mediaType"] == mtype


def test_get_conversation_messages_timeline_returns_history_chronologically(tmp_path):
    store = LocalMasterKeyStore(_key_file(tmp_path))
    core = create_gateway_core(storage_root=tmp_path / "storage", secret_store=store)
    ctx = _context()

    # 1. 创建会话
    c_resp = core.handle(VerifiedGatewayRequest(
        context=ctx, method="POST", target="/open-android-intelligence/v2/conversations",
        idempotencyKey="req_local", body={"clientConversationId": "conv_tm_1"}, now="2026-09-17T10:00:00.000Z",
    ))
    conv_id = c_resp["data"]["conversation"]["conversationId"]

    # 2. 发送用户消息
    ctx_msg = VerifiedRequestContext(
        accountId=ACCOUNT_ID, deviceId="dev_local", sessionId="sess_local",
        requestId="req_msg_1", correlationId="cor_msg_1",
        pairingGeneration=1, grantRevision=1,
    )
    core.handle(VerifiedGatewayRequest(
        context=ctx_msg, method="POST", target=f"/open-android-intelligence/v2/conversations/{conv_id}/messages",
        idempotencyKey="req_msg_1", body={"clientMessageId": "cmsg_1", "text": "用户提问", "attachments": []},
        now="2026-09-17T10:00:01.000Z",
    ))

    # 3. 记录助手回复
    account = core.open_gateway_account(ACCOUNT_ID)
    account.conversations.record_assistant_message(conv_id, "msg_reply_1", "助手回答内容", now="2026-09-17T10:00:05.000Z")
    account.close()

    # 4. GET 时间线（带 query 参数）
    ctx_get = VerifiedRequestContext(
        accountId=ACCOUNT_ID, deviceId="dev_local", sessionId="sess_local",
        requestId="req_get_1", correlationId="cor_get_1",
        pairingGeneration=1, grantRevision=1,
    )
    res = core.handle(VerifiedGatewayRequest(
        context=ctx_get, method="GET", target=f"/open-android-intelligence/v2/conversations/{conv_id}/messages?limit=50",
        idempotencyKey=None, body=None, now="2026-09-17T10:00:10.000Z",
    ))
    assert "error" not in res
    msgs = res["data"]["messages"]
    assert len(msgs) == 2
    assert msgs[0]["sender"] == "user" and msgs[0]["text"] == "用户提问"
    assert msgs[1]["sender"] == "assistant" and msgs[1]["text"] == "助手回答内容"
    assert isinstance(msgs[0]["timestamp"], int) and msgs[0]["timestamp"] > 1_000_000_000_000
    assert isinstance(msgs[1]["timestamp"], int) and msgs[1]["timestamp"] > 1_000_000_000_000
    assert msgs[0]["timestamp"] < msgs[1]["timestamp"]

def test_timeline_messages_include_attachment_metadata_and_adapter_upstream(tmp_path: Path) -> None:
    store = LocalMasterKeyStore(_key_file(tmp_path))
    core = create_gateway_core(storage_root=tmp_path / "storage", secret_store=store)

    adapter = OpenAndroidPlatformAdapter(_Config(), _services(core))
    assert adapter.authorization_is_upstream is True

    # 1. 创建附件
    account = core.open_gateway_account(ACCOUNT_ID)
    att = account.attachments.create(
        clientAttachmentId="c_att_1", filename="photo.png",
        mediaType="image/png", sizeBytes=4, sha256=hashlib.sha256(b"test").hexdigest(),
        correlationId="cor_att_1", now="2026-09-17T10:00:00.000Z",
    )
    att_id = att["attachmentId"]
    account.attachments.upload_content(att_id, b"test", now="2026-09-17T10:00:01.000Z")
    account.attachments.commit(att_id, now="2026-09-17T10:00:02.000Z")
    account.close()

    # 2. 创建会话
    ctx_conv = VerifiedRequestContext(
        accountId=ACCOUNT_ID, deviceId="dev_local", sessionId="sess_local",
        requestId="req_conv_att", correlationId="cor_conv_att",
        pairingGeneration=1, grantRevision=1,
    )
    c_resp = core.handle(VerifiedGatewayRequest(
        context=ctx_conv, method="POST", target="/open-android-intelligence/v2/conversations",
        idempotencyKey="req_conv_att", body={"clientConversationId": "client_c1", "title": "附件会话"},
        now="2026-09-17T10:00:03.000Z",
    ))
    conv_id = c_resp["data"]["conversation"]["conversationId"]

    # 3. 发送带附件消息
    ctx_msg = VerifiedRequestContext(
        accountId=ACCOUNT_ID, deviceId="dev_local", sessionId="sess_local",
        requestId="req_msg_att", correlationId="cor_msg_att",
        pairingGeneration=1, grantRevision=1,
    )
    p_res = core.handle(VerifiedGatewayRequest(
        context=ctx_msg, method="POST", target=f"/open-android-intelligence/v2/conversations/{conv_id}/messages",
        idempotencyKey="req_msg_att", body={"clientMessageId": "cmsg_att", "text": "", "attachments": [{"attachmentId": att_id}]},
        now="2026-09-17T10:00:04.000Z",
    ))
    assert "error" not in p_res

    # 4. 拉取消息列表，验证附件元数据
    ctx_get = VerifiedRequestContext(
        accountId=ACCOUNT_ID, deviceId="dev_local", sessionId="sess_local",
        requestId="req_get_att", correlationId="cor_get_att",
        pairingGeneration=1, grantRevision=1,
    )
    res = core.handle(VerifiedGatewayRequest(
        context=ctx_get, method="GET", target=f"/open-android-intelligence/v2/conversations/{conv_id}/messages",
        idempotencyKey=None, body=None, now="2026-09-17T10:00:05.000Z",
    ))
    msgs = res["data"]["messages"]
    assert len(msgs) == 1
    parts = msgs[0]["parts"]
    assert len(parts) == 1
    assert parts[0]["type"] == "attachment"
    assert parts[0]["attachmentId"] == att_id
    assert parts[0]["filename"] == "photo.png"
    assert parts[0]["mediaType"] == "image/png"
