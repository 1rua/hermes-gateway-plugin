"""History must stay readable beyond the default page and survive reopening."""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from open_android_intelligence_gateway.core import GatewayError, create_gateway_core
from test_support import make_secret_store


def _history(tmp_path, count=121):
    core = create_gateway_core(tmp_path, secret_store=make_secret_store())
    account = core.open_gateway_account("acct_history")
    when = datetime.now(timezone.utc) - timedelta(minutes=10)
    cid = account.conversations.create("cc_history", "History", "cor_create")["conversationId"]
    for i in range(count):
        account.conversations.accept_message(
            cid, f"cm_{i}", f"message {i}", [], "dev_history", f"req_{i}", f"cor_{i}",
            now=when + timedelta(seconds=i // 3), dispatch_to_agent=False,
        )
    return core, account, cid


def test_pages_include_every_message_with_equal_timestamps_and_stable_revision(tmp_path):
    core, account, cid = _history(tmp_path)
    cursor, seen, revisions = None, [], set()
    while True:
        page = account.conversations.list_messages(cid, cursor=cursor, limit=23)
        seen.extend(m["messageId"] for m in page["messages"])
        revisions.add(page["snapshotRevision"])
        cursor = page["nextCursor"]
        if cursor is None:
            break
    assert len(seen) == len(set(seen)) == 121
    assert len(revisions) == 1
    assert next(iter(revisions)) > 1
    account.close()
    reopened = core.open_gateway_account("acct_history")
    try:
        assert reopened.conversations.list_messages(cid, client_message_id="cm_120")["messages"][0]["text"] == "message 120"
    finally:
        reopened.close()


def test_cursor_is_bound_to_conversation_and_rejects_tampering(tmp_path):
    _, account, cid = _history(tmp_path, 4)
    try:
        cursor = account.conversations.list_messages(cid, limit=2)["nextCursor"]
        other = account.conversations.create("cc_other", "Other", "cor_other")["conversationId"]
        for bad in (cursor[:-3] + "zzz", cursor):
            with pytest.raises(GatewayError):
                account.conversations.list_messages(other, cursor=bad, limit=2)
    finally:
        account.close()


def test_snapshot_revision_changes_when_existing_message_is_edited(tmp_path):
    _, account, cid = _history(tmp_path, 1)
    try:
        account.conversations.record_assistant_message(cid, "msg_assistant", "first")
        before = account.conversations.list_messages(cid)["snapshotRevision"]
        account.conversations.record_assistant_message(cid, "msg_assistant", "edited")
        assert account.conversations.list_messages(cid)["snapshotRevision"] > before
    finally:
        account.close()
