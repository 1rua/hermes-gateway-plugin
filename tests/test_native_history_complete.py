"""Optional host integration; run with the verified Hermes checkout on PYTHONPATH."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from open_android_intelligence_gateway.core import create_gateway_core
from open_android_intelligence_gateway.host_history import HermesHistoryPort
from test_support import make_secret_store


def test_legacy_history_reaches_native_session_db_before_bounded_maintenance_erases_it(tmp_path):
    SessionDB = pytest.importorskip("hermes_state").SessionDB
    native_path = tmp_path / "native.db"
    database = SessionDB(native_path)
    core = create_gateway_core(tmp_path / "gateway", secret_store=make_secret_store())
    account = core.open_gateway_account("acct_history")
    old = datetime.now(timezone.utc) - timedelta(days=2)
    conversations = []
    try:
        for index in range(17):
            cid = account.conversations.create(f"cc_{index}", "Legacy", f"cor_{index}", now=old)["conversationId"]
            sid = f"native_{index}"
            database.create_session(sid, "open_android")
            account.agent_sessions.record(cid, "inbound-message", now=old)
            assert account.agent_sessions.attach(cid, sid)
            accepted = account.conversations.accept_message(cid, f"cm_{index}", f"legacy user {index}", [], "dev_history",
                f"req_{index}", f"cor_{index}", now=old)
            # This is an adopted row from the pre-migration Gateway schema.
            account.store.database.execute("UPDATE conversation_message_dispatch SET status='completed' WHERE message_id=?", (accepted["messageId"],))
            account.conversations.record_assistant_message(cid, f"msg_reply_{index}", f"legacy reply {index}", now=old)
            conversations.append((cid, sid, accepted["messageId"]))
        # One transcript already owns its inbound; migrating must not duplicate it.
        database.append_message("native_0", "user", "legacy user 0", platform_message_id="cm_0", timestamp=old.timestamp())
    finally:
        account.close()

    port = HermesHistoryPort(core, SimpleNamespace(_db=database))
    core.history_reader = port.read
    try:
        port.maintain("acct_history")
        account = core.open_gateway_account("acct_history")
        try:
            # Seven conversations remain untouched by the first ten-thread sweep.
            assert account.store.database.execute("SELECT COUNT(*) FROM messages WHERE text!=''").fetchone()[0] == 14
        finally:
            account.close()
        port.maintain("acct_history")
        port.maintain("acct_history")
        account = core.open_gateway_account("acct_history")
        try:
            assert account.store.database.execute("SELECT COUNT(*) FROM messages WHERE text!=''").fetchone()[0] == 0
            for cid, sid, mid in conversations:
                assert len(database.get_messages(sid, include_inactive=True)) == 2
                rows = account.conversations.list_messages(cid, client_message_id=f"cm_{sid.removeprefix('native_')}")["messages"]
                assert rows[0]["messageId"] == mid
                assert rows[0]["text"].startswith("legacy user")
        finally:
            account.close()
    finally:
        database.close()

    database = SessionDB(native_path)
    try:
        reopened = create_gateway_core(tmp_path / "gateway", secret_store=make_secret_store())
        reopened.history_reader = HermesHistoryPort(reopened, SimpleNamespace(_db=database)).read
        account = reopened.open_gateway_account("acct_history")
        try:
            assert len(account.conversations.list_messages(conversations[-1][0])["messages"]) == 2
        finally:
            account.close()
    finally:
        database.close()
