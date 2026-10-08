"""History stays in Hermes' SessionDB; Gateway stores only stable wire bindings.

The session ID is read from the account's host-created binding. Neither an HTTP
request nor a model parameter may supply a database path or select a host session.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone, timedelta
import threading
from typing import Any, Mapping
from .history_media import HistoryMedia


def visible_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(str(part.get("text", "")) for part in content
                       if isinstance(part, Mapping) and part.get("type") == "text")
    return ""


class HermesHistoryPort:
    def __init__(self, core: Any, session_store: Any):
        self.core = core
        self.session_store = session_store
        self.started_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00","Z")
        self._migration_lock = threading.RLock()

    def read(self, account_id: str, conversation_id: str) -> list[dict[str, Any]]:
        account = self.core.open_gateway_account(account_id)
        try:
            binding = account.agent_sessions.lookup(conversation_id)
            if not binding or not binding.get("agentSessionId"):
                return []
            # These are the verified Hermes v0.20+ native transcript APIs.
            database = getattr(self.session_store, "_db", None)
            if database is None or not callable(getattr(database, "get_messages", None)):
                raise RuntimeError("HOST_HISTORY_UNAVAILABLE")
            session_id = binding["agentSessionId"]
            rows = database.get_messages(session_id, include_inactive=True)

            # The first feature startup fences legacy import. New turns are
            # written by Hermes, even if the transport already acknowledged them.
            with self._migration_lock, account.store.transaction():
                account.store.database.execute("INSERT OR IGNORE INTO account_metadata(key,value) VALUES ('native-history-migration-cutoff',?)",(self.started_at,))
                cutoff = account.store.database.execute("SELECT value FROM account_metadata WHERE key='native-history-migration-cutoff'").fetchone()[0]
                rows = database.get_messages(session_id,include_inactive=True)
                by_platform = {str(row["platform_message_id"]):row for row in rows if row.get("platform_message_id")}
                remaining = list(rows)
                queued = account.store.database.execute(
                    "SELECT m.* FROM messages m LEFT JOIN conversation_message_dispatch d ON d.message_id=m.message_id "
                    "WHERE m.conversation_id=? AND m.text!='' AND (m.sender='assistant' OR d.status IN ('delivered','completed')) "
                    "ORDER BY m.created_at,m.message_id LIMIT 1000",(conversation_id,),
                ).fetchall()
                for row in queued:
                    generation = account.conversations.workflow.for_message(row["message_id"])
                    if generation and generation.get("offsets") and row["message_id"] != generation["messageIds"][0]: continue
                    text = account.store.open_json(row["text"],f"message:{row['message_id']}:text")
                    native = by_platform.get(row["client_message_id"])
                    if native is None and row["created_at"] <= cutoff:
                        native = next((item for item in remaining if item.get("role") == row["sender"] and visible_text(item.get("content")) == str(text)),None)
                        if native is None:
                            from .core import _now
                            native_id = database.append_message(session_id,row["sender"],str(text),platform_message_id=row["client_message_id"],timestamp=_now(row["created_at"]).timestamp())
                            native = {"id":native_id,"platform_message_id":row["client_message_id"]}
                        else:
                            remaining.remove(native)
                    if native is None: continue
                    native_key = "history-native:" + hashlib.sha256(f"{session_id}:{native['id']}".encode()).hexdigest()
                    account.store.database.execute("INSERT OR IGNORE INTO account_metadata(key,value) VALUES (?,?)",(native_key,row["message_id"]))
                    for mid in generation["messageIds"] if generation and generation.get("offsets") else [row["message_id"]]:
                        account.store.database.execute("UPDATE messages SET text='' WHERE message_id=?",(mid,))
                rows = database.get_messages(session_id,include_inactive=True)

            result = []
            for row in rows:
                role = row.get("role")
                if role not in {"user", "assistant"}:
                    continue
                native_id = f"{session_id}:{row['id']}"
                text = visible_text(row.get("content"))
                native_key = "history-native:" + hashlib.sha256(native_id.encode()).hexdigest()
                mapped = account.store.database.execute("SELECT value FROM account_metadata WHERE key=?", (native_key,)).fetchone()
                client_id = row.get("platform_message_id")
                protocol = account.store.database.execute(
                    "SELECT message_id,client_message_id FROM messages WHERE conversation_id=? AND client_message_id=? AND sender=?",
                    (conversation_id, client_id, role),
                ).fetchone() if client_id else None
                if mapped:
                    message_id = mapped[0]
                elif protocol:
                    message_id = protocol[0]
                else:
                    digest = hashlib.sha256(text.encode()).hexdigest()
                    prefix = f"history-hash:{conversation_id}:"
                    candidate = account.store.database.execute(
                        "SELECT key FROM account_metadata WHERE key LIKE ? AND value=? ORDER BY key LIMIT 1",
                        (prefix + "%", digest),
                    ).fetchone()
                    message_id = candidate[0][len(prefix):] if candidate else "msg_host_" + hashlib.sha256(
                        f"{account_id}:{conversation_id}:{native_id}".encode()).hexdigest()[:40]
                    if candidate:
                        account.store.database.execute("DELETE FROM account_metadata WHERE key=?", (candidate[0],))
                account.store.database.execute("INSERT OR IGNORE INTO account_metadata(key,value) VALUES (?,?)", (native_key, message_id))
                timestamp = row.get("timestamp")
                try:
                    millis = int(float(timestamp) * 1000) if isinstance(timestamp, (float, int)) else int(
                        datetime.fromisoformat(str(timestamp).replace("Z", "+00:00")).timestamp() * 1000)
                except (ValueError, TypeError):
                    millis = int(row["id"])
                inactive = row.get("active", 1) in (0, False)
                result.append({"messageId": message_id, "clientMessageId": client_id, "conversationId": conversation_id,
                               "sender": role, "text": "" if inactive else text,
                               "parts": [] if inactive else [{"type": "text", "text": text}]+HistoryMedia(account).reply_parts(message_id),
                               "timestamp": millis, "state": "DELETED" if inactive else "CONFIRMED"})
            return [expanded for item in result for expanded in account.conversations.workflow.expand_history(item)]
        finally:
            account.close()


    def maintain(self,account_id: str,now: datetime | None = None) -> None:
        account = self.core.open_gateway_account(account_id)
        try:
            saved = account.store.database.execute("SELECT value FROM account_metadata WHERE key='native-history-maintenance-offset'").fetchone()
            offset = int(saved[0]) if saved else 0
            conversations = account.store.database.execute("SELECT conversation_id FROM conversation_agent_sessions WHERE agent_session_id IS NOT NULL ORDER BY conversation_id LIMIT 10 OFFSET ?",(offset,)).fetchall()
        finally: account.close()
        for row in conversations: self.read(account_id,row[0])
        account = self.core.open_gateway_account(account_id)
        try:
            next_offset = offset + len(conversations) if len(conversations) == 10 else 0
            account.store.database.execute("INSERT OR REPLACE INTO account_metadata(key,value) VALUES ('native-history-maintenance-offset',?)",(str(next_offset),))
            from .core import iso_millis
            cutoff = iso_millis((now or datetime.now(timezone.utc))-timedelta(seconds=self.core.attachment_policy.attachment_ttl_seconds))
            # Legacy adopted history must reach the native database before its
            # transport copy is erased; the bounded migration walks 10 threads
            # per maintenance tick and may not have visited this thread yet.
            migration=account.store.database.execute("SELECT value FROM account_metadata WHERE key='native-history-migration-cutoff'").fetchone()
            legacy_cutoff=migration[0] if migration else self.started_at
            account.store.database.execute("UPDATE messages SET text='' WHERE message_id IN (SELECT m.message_id FROM messages m LEFT JOIN conversation_message_dispatch d ON d.message_id=m.message_id WHERE m.text!='' AND m.created_at<=? AND (m.created_at>? OR (m.sender='user' AND (d.status IS NULL OR d.status NOT IN ('delivered','completed')))) LIMIT 1000)",(cutoff,legacy_cutoff))
        finally: account.close()


def host_history_page(port: Any, conversation_id: str, client_id: str | None, cursor: str | None, limit: int) -> dict[str, Any]:
    from .core import GatewayError, _jcs
    messages = port.history_reader(port.account_id, conversation_id)
    by_id = {row["messageId"]: row for row in messages}
    # Only unadopted transport messages remain in the Gateway body queue.
    pending = port.store.database.execute("SELECT * FROM messages WHERE conversation_id=? AND text!=''", (conversation_id,)).fetchall()
    for row in pending:
        if row["message_id"] not in by_id:
            text = port.store.open_json(row["text"], f"message:{row['message_id']}:text")
            by_id[row["message_id"]] = {"messageId": row["message_id"], "clientMessageId": row["client_message_id"],
                "conversationId": conversation_id, "sender": row["sender"], "text": text,
                "parts": [{"type": "text", "text": text}], "createdAt": row["created_at"],
                "timestamp": int(datetime.fromisoformat(row["created_at"].replace("Z", "+00:00")).timestamp()*1000), "state": row["state"]}
    if client_id and not any(row.get("clientMessageId") == client_id for row in by_id.values()):
        known = port.store.database.execute("SELECT * FROM messages WHERE conversation_id=? AND client_message_id=?",(conversation_id,client_id)).fetchone()
        if known:
            by_id[known["message_id"]] = {"messageId":known["message_id"],"clientMessageId":client_id,"conversationId":conversation_id,
                "sender":known["sender"],"text":"","parts":[],"timestamp":int(datetime.fromisoformat(known["created_at"].replace("Z","+00:00")).timestamp()*1000),"state":known["state"]}
    rows = sorted(by_id.values(), key=lambda row: (row["timestamp"], row["messageId"]))
    revision = int(hashlib.sha256(_jcs(rows).encode()).hexdigest()[:13], 16) + 1
    offset = 0
    if cursor:
        saved = port.store.open_json(cursor, f"host-timeline:{conversation_id}")
        if saved.get("revision") != revision:
            raise GatewayError("CURSOR_EXPIRED", {"recoverableResources": ["conversations"]})
        offset = saved.get("offset")
        if not isinstance(offset, int) or offset < 0 or offset > len(rows):
            raise GatewayError("SCHEMA_INVALID")
    if client_id:
        rows = [row for row in rows if row.get("clientMessageId") == client_id]
    size = max(1, min(int(limit), 100))
    end = offset + size
    next_cursor = port.store.seal_json({"offset": end, "revision": revision}, f"host-timeline:{conversation_id}") if end < len(rows) else None
    return {"messages": rows[offset:end], "nextCursor": next_cursor, "snapshotRevision": revision}
