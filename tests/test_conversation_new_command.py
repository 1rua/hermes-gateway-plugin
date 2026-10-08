"""`/new` is the Agent host's own way to start a thread (contract §7.1).

The phone never decides the new conversation's identity: it sends `/new` as an
ordinary message into the thread it is leaving, and this command entry answers
with the id it created. Everything below drives the real Core seam — schema
validation, idempotency ledger and event stream — so a host that merely records
the text, or that invents a second thread per retry, fails here instead of
disagreeing with the phone in production.
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from open_android_intelligence_gateway.core import create_gateway_core
from test_support import make_secret_store, trust_core

ACCOUNT_ID = "acct_new_command"
CONVERSATIONS = "/open-android-intelligence/v2/conversations"
NEW_COMMAND_REQUEST_ID = "req_new_command"
NEW_COMMAND_CORRELATION_ID = "cor_new_command"


_real_create_gateway_core = create_gateway_core


def create_gateway_core(storage_root=None, **options):
    options.setdefault("secret_store", make_secret_store())
    return trust_core(_real_create_gateway_core(storage_root=storage_root, **options))


def _context(request_id: str = NEW_COMMAND_REQUEST_ID, correlation_id: str = NEW_COMMAND_CORRELATION_ID) -> dict:
    return {
        "accountId": ACCOUNT_ID,
        "deviceId": "dev_new_command",
        "sessionId": "sess_new_command",
        "requestId": request_id,
        "correlationId": correlation_id,
        "pairingGeneration": 1,
        "grantRevision": 1,
    }


def _send(core, conversation_id: str, text: str, request_id: str = NEW_COMMAND_REQUEST_ID) -> dict:
    return core.handle({
        "method": "POST",
        "target": f"{CONVERSATIONS}/{conversation_id}/messages",
        "context": _context(request_id),
        "body": {"clientMessageId": f"msg_{request_id}", "text": text, "attachments": []},
        "idempotencyKey": request_id,
    })


def _list(core) -> list[dict]:
    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        return account.conversations.list()
    finally:
        account.close()


def _messages(core, conversation_id: str) -> list[dict]:
    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        return account.conversations.list_messages(conversation_id)["messages"]
    finally:
        account.close()


def _events(core, event_type: str) -> list[dict]:
    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        events = account.events.read_after(None)
    finally:
        account.close()
    return [event for event in events if event["eventType"] == event_type]


def _seed(core) -> str:
    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        created = account.conversations.create("cconv_source", "来源会话", "cor_source")
    finally:
        account.close()
    return created["conversationId"]


def test_new_command_creates_a_thread_and_names_it_in_the_event(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    source = _seed(core)

    response = _send(core, source, "/new")

    assert response["data"]["message"]["status"] == "accepted"
    created = [row for row in _list(core) if row["conversationId"] != source]
    assert len(created) == 1, "必须恰好新建一个会话"

    events = _events(core, "conversation.command.result")
    assert len(events) == 1
    payload = events[0]["payload"]
    assert payload["command"] == "new"
    assert payload["commandId"] == "new"
    assert payload["outcome"] == "created-conversation"
    assert payload["sourceConversationId"] == source
    assert payload["sourceMessageId"] == response["data"]["message"]["messageId"]
    assert payload["conversationId"] == created[0]["conversationId"]


def test_command_stays_in_the_source_thread_and_the_new_one_starts_empty(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    source = _seed(core)

    response = _send(core, source, "/new")
    created_id = _events(core, "conversation.command.result")[0]["payload"]["conversationId"]

    source_messages = [message["text"] for message in _messages(core, source)]
    assert source_messages == ["/new"], "命令必须留在来源线程"
    assert _messages(core, created_id) == [], "新线程必须从空上下文开始"
    assert response["data"]["message"]["conversationId"] == source


def test_messages_after_the_answer_belong_to_the_named_conversation(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    source = _seed(core)

    _send(core, source, "/new")
    created_id = _events(core, "conversation.command.result")[0]["payload"]["conversationId"]

    follow_up = _send(core, created_id, "这条必须进新会话", request_id="req_follow_up")
    assert follow_up["data"]["message"]["conversationId"] == created_id
    assert [message["text"] for message in _messages(core, created_id)] == ["这条必须进新会话"]


def test_replayed_request_answers_with_the_same_conversation(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    source = _seed(core)

    first = _send(core, source, "/new")
    first_id = _events(core, "conversation.command.result")[0]["payload"]["conversationId"]
    second = _send(core, source, "/new")

    created = [row for row in _list(core) if row["conversationId"] != source]
    assert len(created) == 1, "同一幂等请求不得重复创建第二个会话"
    assert second["data"] == first["data"]
    assert len(_events(core, "conversation.command.result")) == 1


def _bindings(core) -> list[dict]:
    account = core.open_gateway_account(ACCOUNT_ID)
    try:
        return account.agent_sessions.list()
    finally:
        account.close()


def test_new_command_records_the_binding_the_host_fills_in(tmp_path):
    """ADR 0043: the command entry saves the binding in the same transaction."""
    core = create_gateway_core(storage_root=tmp_path)
    source = _seed(core)

    _send(core, source, "/new")
    created_id = _events(core, "conversation.command.result")[0]["payload"]["conversationId"]

    bindings = _bindings(core)
    assert [row["conversationId"] for row in bindings] == [created_id]
    # The protocol layer never invents the host's session id: it records that the
    # conversation owes one, and the host runtime names it when it creates it.
    assert bindings[0]["agentSessionId"] is None
    assert bindings[0]["sessionKey"] is None
    assert bindings[0]["createdVia"] == "new-command"
    assert bindings[0]["requestId"] == NEW_COMMAND_REQUEST_ID


def test_the_source_conversation_is_never_rebound(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    source = _seed(core)

    _send(core, source, "/new")

    assert source not in [row["conversationId"] for row in _bindings(core)]


def test_replaying_the_command_does_not_add_a_second_binding(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    source = _seed(core)

    _send(core, source, "/new")
    _send(core, source, "/new")

    assert len(_bindings(core)) == 1


def test_plain_messages_add_no_binding_in_the_protocol_layer(tmp_path):
    """A binding is an authority statement, not a side effect of any message."""
    core = create_gateway_core(storage_root=tmp_path)
    source = _seed(core)

    _send(core, source, "普通消息", request_id="req_plain")

    assert _bindings(core) == []


def test_new_with_arguments_is_plain_text_the_agent_interprets(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    source = _seed(core)

    _send(core, source, "/new 不是命令", request_id="req_not_a_command")

    assert [row for row in _list(core) if row["conversationId"] != source] == []
    assert _events(core, "conversation.command.result") == []
    assert [message["text"] for message in _messages(core, source)] == ["/new 不是命令"]


def _negotiation_body(schema_hash: str) -> dict:
    return {
        "negotiationId": "neg_new_command",
        "protocol": {"major": 2, "minor": 1},
        "client": {
            "installationId": "install_new_command",
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
            "conversationUi": ["agent-command-catalog-v1", "agent-command-new-v1"],
        },
        "schemaHashes": {"core": schema_hash},
    }


def _negotiate(core, schema_hash: str) -> dict:
    return core.handle({
        "method": "POST",
        "target": "/open-android-intelligence/v2/negotiate",
        "context": _context(request_id="req_negotiate", correlation_id="cor_negotiate"),
        "body": _negotiation_body(schema_hash),
        "idempotencyKey": "req_negotiate",
    })


def test_negotiation_still_requires_the_real_schema_digest(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    response = _negotiate(core, "sha256:" + "0" * 64)
    assert response["error"]["code"] == "PROTOCOL_INCOMPATIBLE", response


def test_refused_negotiation_names_both_digests_for_the_operator(tmp_path, caplog):
    """A digest mismatch is a destructive upgrade, and nothing else records it.

    The refusal happens before authentication, so no session, audit row or event
    survives it: this log line is the only thing that can tell an operator which
    side is stale, and only prefixes of the two public digests are logged.
    """
    from open_android_intelligence_gateway.core import ContractRegistry

    core = create_gateway_core(storage_root=tmp_path)
    with caplog.at_level(logging.WARNING, logger="open_android_intelligence_gateway.core"):
        response = _negotiate(core, "sha256:" + "0" * 64)

    assert response["error"]["code"] == "PROTOCOL_INCOMPATIBLE", response
    refused = [record.getMessage() for record in caplog.records if "Refused negotiation" in record.getMessage()]
    assert len(refused) == 1, refused
    assert "installationId=install_new_command" in refused[0]
    assert "appVersion=2.0.0" in refused[0]
    assert "clientCore=sha256:00000000" in refused[0]
    assert f"gatewayCore={ContractRegistry().core_schema_hash[:15]}" in refused[0]


def test_accepted_negotiation_logs_no_refusal(tmp_path, caplog):
    """Only real refusals may warn: a noisy handshake would hide the signal."""
    from open_android_intelligence_gateway.core import ContractRegistry

    core = create_gateway_core(storage_root=tmp_path)
    with caplog.at_level(logging.WARNING, logger="open_android_intelligence_gateway.core"):
        response = _negotiate(core, ContractRegistry().core_schema_hash)

    assert response["data"], response
    assert [record.getMessage() for record in caplog.records if "Refused negotiation" in record.getMessage()] == []


def test_negotiation_advertises_the_command_entry_it_really_serves(tmp_path):
    from open_android_intelligence_gateway.core import ContractRegistry

    core = create_gateway_core(storage_root=tmp_path)
    response = _negotiate(core, ContractRegistry().core_schema_hash)

    features = response["data"]["features"]
    # The phone asks for `/new` on every connection; agreeing here is a promise
    # that this host actually owns the command entry behind it.
    assert "agent-command-new-v1" in features["conversationUi"]
    assert sorted(features["conversationUi"]) == ["agent-command-catalog-v1", "agent-command-new-v1"]


def test_command_body_is_unknown_outside_the_source_conversation(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    source = _seed(core)

    missing = _send(core, "conv_does_not_exist", "/new", request_id="req_missing")

    assert missing["error"]["code"] == "SCHEMA_INVALID"
    assert [row for row in _list(core) if row["conversationId"] != source] == []
