"""Durable, body-free generation and batch identities for native Agent turns."""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping


def validate_batch(body: Any, conversation_id: str) -> list[Mapping[str, Any]]:
    from .core import GatewayError
    if not isinstance(body, Mapping) or set(body) - {"clientBatchId", "clientConversationId", "joinMode", "members"}:
        raise GatewayError("SCHEMA_INVALID")
    if not re.fullmatch(r"[A-Za-z0-9._~-]{1,128}", str(body.get("clientBatchId", ""))) or body.get("joinMode") != "newline-v1":
        raise GatewayError("SCHEMA_INVALID")
    if body.get("clientConversationId", conversation_id) != conversation_id:
        raise GatewayError("SCHEMA_INVALID")
    members = body.get("members")
    if not isinstance(members, list) or not 1 <= len(members) <= 20:
        raise GatewayError("SCHEMA_INVALID")
    seen: set[str] = set()
    for member in members:
        if not isinstance(member, Mapping) or set(member) != {"clientMessageId", "text"}:
            raise GatewayError("SCHEMA_INVALID")
        mid, text = member["clientMessageId"], member["text"]
        if not isinstance(mid, str) or not re.fullmatch(r"[A-Za-z0-9._~-]{1,128}", mid) or mid in seen:
            raise GatewayError("SCHEMA_INVALID")
        if not isinstance(text, str) or not text or text.lstrip().startswith("/"):
            raise GatewayError("SCHEMA_INVALID")
        seen.add(mid)
    if len("\n".join(m["text"] for m in members).encode()) > 64 * 1024:
        raise GatewayError("SCHEMA_INVALID")
    return members


class ConversationWorkflow:
    def __init__(self, port: Any):
        self.port, self.store = port, port.store

    def _get(self, key: str) -> Any:
        row = self.store.database.execute("SELECT value FROM account_metadata WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def _put(self, key: str, value: Any) -> None:
        self.store.database.execute("INSERT OR REPLACE INTO account_metadata(key,value) VALUES (?,?)", (key, json.dumps(value, separators=(",", ":"))))

    def register(self, accepted: Mapping[str, Any], device_id: str, created_at: str) -> str:
        mid = accepted["messageId"]
        gid = "gen_" + hashlib.sha256(mid.encode()).hexdigest()[:40]
        order = (self._get("generation-order") or 0) + 1
        self._put("generation-order",order)
        self._put("generation:" + gid, {"order":order,"generationId": gid, "conversationId": accepted["conversationId"],
                  "messageIds": [mid], "deviceId": device_id, "state": "queued", "createdAt": created_at})
        self._put("message-generation:" + mid, gid)
        return gid

    def for_message(self, message_id: str) -> dict[str, Any] | None:
        gid = self._get("message-generation:" + message_id)
        return self._get("generation:" + gid) if gid else None

    def current(self,conversation_id: str) -> dict[str,Any] | None:
        self.port.get(conversation_id)
        rows=[json.loads(r[0]) for r in self.store.database.execute("SELECT value FROM account_metadata WHERE key LIKE 'generation:%'")]
        active=sorted((r for r in rows if r['conversationId']==conversation_id and r['state'] in {'queued','running','unknown'}),key=lambda r:(r['state']=='queued',r.get('order',0)))
        return {k:active[0][k] for k in ('generationId','conversationId','state')} if active else None

    def accept_batch(self, conversation_id: str, body: Any, context: Mapping[str, Any], now: Any) -> dict[str, Any]:
        from .core import GatewayError, _jcs
        members = validate_batch(body, conversation_id)
        key = "batch:" + conversation_id + ":" + body["clientBatchId"]
        digest = hashlib.sha256(_jcs(body).encode()).hexdigest()
        prior = self._get(key)
        if prior:
            if prior["digest"] != digest or prior["deviceId"] != context["deviceId"]:
                raise GatewayError("IDEMPOTENCY_CONFLICT")
            return prior["acceptance"]
        # A member belongs to exactly one accepted sending unit, including when
        # a caller retries with another HTTP request or batch identity.
        for member in members:
            if self.store.database.execute("SELECT 1 FROM messages WHERE conversation_id=? AND client_message_id=?", (conversation_id, member["clientMessageId"])).fetchone():
                raise GatewayError("IDEMPOTENCY_CONFLICT")
        accepted = [self.port.accept_message(conversation_id, m["clientMessageId"], m["text"], [], context["deviceId"],
                    context["requestId"], context["correlationId"], now, emit_queued=False) for m in members]
        leader = accepted[0]["messageId"]
        generation = self.for_message(leader)
        assert generation is not None
        gid = generation["generationId"]
        offsets, start = [], 0
        for member, ack in zip(members, accepted):
            offsets.append({"messageId": ack["messageId"], "clientMessageId": member["clientMessageId"], "start": start, "length": len(member["text"])})
            start += len(member["text"]) + 1
            if ack["messageId"] != leader:
                self.store.database.execute("DELETE FROM conversation_message_dispatch WHERE message_id=?", (ack["messageId"],))
                old = self.for_message(ack["messageId"])
                self.store.database.execute("DELETE FROM account_metadata WHERE key=?", ("generation:" + old["generationId"],))
            self._put("message-generation:" + ack["messageId"], gid)
        aggregate = "\n".join(m["text"] for m in members)
        generation.update(messageIds=[a["messageId"] for a in accepted], batchId="batch_" + hashlib.sha256(key.encode()).hexdigest()[:40],
                          offsets=offsets, aggregateSha256=hashlib.sha256(aggregate.encode()).hexdigest())
        self._put("generation:" + gid, generation)
        for member, ack in zip(members, accepted):
            self.port.events.append("conversation.message.status", context["correlationId"],
                {"conversationId": conversation_id, "messageId": ack["messageId"], "clientMessageId": member["clientMessageId"],
                 "generationId": gid, "status": "queued", "revision": 0, "errorCode": None}, now)
        result = {"batchId": generation["batchId"], "status": "accepted", "generationId": gid,
                  "members": [{"clientMessageId": m["clientMessageId"], "messageId": a["messageId"]} for m, a in zip(members, accepted)]}
        self._put(key, {"digest": digest, "deviceId": context["deviceId"], "acceptance": result})
        return result

    def aggregate(self, message_id: str, original: str) -> str:
        generation = self.for_message(message_id)
        if not generation or not generation.get("offsets"):
            return original
        values = []
        for mid in generation["messageIds"]:
            row = self.store.database.execute("SELECT text FROM messages WHERE message_id=?", (mid,)).fetchone()
            if not row or not row[0]:
                from .core import GatewayError
                raise GatewayError("OUTCOME_UNKNOWN")
            values.append(self.store.open_json(row[0], f"message:{mid}:text"))
        return "\n".join(values)

    def claim(self, message_id: str) -> bool:
        with self.store.transaction():
            generation = self.for_message(message_id)
            if generation is None:  # Upgrade of a legacy transport queue.
                return True
            if generation["state"] != "queued":
                return False
            for row in self.store.database.execute("SELECT value FROM account_metadata WHERE key LIKE 'generation:%'"):
                other = json.loads(row[0])
                if other["generationId"] != generation["generationId"] and other["conversationId"] == generation["conversationId"]:
                    if other["state"] in {"running", "unknown"} or (other["state"] == "queued" and other.get("order",0) < generation.get("order",0)):
                        return False
            generation["state"] = "running"
            self._put("generation:" + generation["generationId"], generation)
            return True

    def settle(self, message_id: str, state: str) -> None:
        generation = self.for_message(message_id)
        if generation and generation["state"] in {"queued", "running", "unknown"}:
            generation["state"] = state
            self._put("generation:" + generation["generationId"], generation)

    def prepare_cancel(self, conversation_id: str, generation_id: str, context: Mapping[str, Any], cancel: Any) -> str:
        from .core import GatewayError
        with self.store.transaction():
            generation = self._get("generation:" + generation_id)
            if not generation or generation["conversationId"] != conversation_id:
                raise GatewayError("SCHEMA_INVALID")
            origin = self._get("message-device:" + generation["messageIds"][0])
            if not origin or origin["deviceId"] != context["deviceId"] or origin["pairingGeneration"] != context["pairingGeneration"]:
                raise GatewayError("PAIRING_GENERATION_STALE")
            if generation["state"] == "cancelled": return "CANCELLED"
            if generation["state"] in {"completed", "failed"}: return "ALREADY_COMPLETED"
            if generation["state"] == "queued":
                self.settle(generation["messageIds"][0], "cancelled")
                self.store.database.execute("UPDATE conversation_message_dispatch SET status='failed',error_code='AGENT_UNAVAILABLE',claim_token=NULL,claim_until=NULL WHERE message_id=?", (generation["messageIds"][0],))
                return "CANCELLED"
            if cancel is None: return "UNSUPPORTED"
            # Pause this thread before crossing the native cancellation boundary.
            generation["state"] = "unknown"
            self._put("generation:" + generation_id, generation)
        try:
            return cancel(conversation_id, generation_id)
        except Exception:
            return "OUTCOME_UNKNOWN"

    def finish_cancel(self, conversation_id: str, generation_id: str, outcome: str, context: Mapping[str, Any], now: Any) -> dict[str, Any]:
        from .core import GatewayError
        if outcome not in {"CANCELLED", "ALREADY_COMPLETED", "UNSUPPORTED", "OUTCOME_UNKNOWN"}:
            raise GatewayError("SCHEMA_INVALID")
        generation = self._get("generation:" + generation_id)
        if not generation: raise GatewayError("SCHEMA_INVALID")
        if outcome == "CANCELLED":
            # The native cancellation receipt is authoritative even if its
            # completion callback raced with this handoff.
            generation["state"] = "cancelled"
            self._put("generation:" + generation_id, generation)
            for mid in generation["messageIds"]:
                self.store.database.execute("UPDATE messages SET text='' WHERE message_id=?", (mid,))
            self.store.database.execute("UPDATE conversation_message_dispatch SET status='failed',error_code='AGENT_UNAVAILABLE',claim_token=NULL,claim_until=NULL WHERE message_id=?", (generation["messageIds"][0],))
            self.port.events.append("conversation.generation.cancelled", context["correlationId"],
                {"conversationId": conversation_id, "generationId": generation_id, "outcome": outcome}, now)
        elif outcome == "ALREADY_COMPLETED": self.settle(generation["messageIds"][0], "completed")
        return {"outcome": outcome, "generationId": generation_id}

    def expand_history(self, row: dict[str, Any]) -> list[dict[str, Any]]:
        generation = self.for_message(row["messageId"])
        if not generation or not generation.get("offsets") or row.get("sender") != "user": return [row]
        text = row.get("text", "")
        if row.get("state") != "DELETED" and hashlib.sha256(text.encode()).hexdigest() != generation["aggregateSha256"]: return [row]
        return [{**row, "messageId": part["messageId"], "clientMessageId": part["clientMessageId"], "batchId": generation["batchId"],
                 "text": "" if row.get("state") == "DELETED" else text[part["start"]:part["start"] + part["length"]],
                 "parts": [] if row.get("state") == "DELETED" else [{"type": "text", "text": text[part["start"]:part["start"] + part["length"]]}]} for part in generation["offsets"]]
