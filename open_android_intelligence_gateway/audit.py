"""Minimal, content-free Gateway audit storage."""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping


# Field names are compared after removing spelling separators so that one
# deny-first policy covers snake_case, camelCase, kebab-case and casing
# variants.  These are intentionally field-name rules: audit callers may keep
# harmless action/result metadata, but a denied branch is never traversed or
# serialized.
_DENIED_FIELD_MARKERS = frozenset(
    {
        "password",
        "credential",
        "secret",
        "token",
        "content",
        "privatekey",
        "accesskey",
        "proof",
        "signature",
        "authorization",
    }
)
_DENIED_FIELD_NAMES = frozenset(
    {
        "message",
        "messages",
        "attachment",
        "attachments",
        "payload",
        "data",
        "details",
        "body",
        "text",
    }
)
# Names that also deny a compound field such as "messageText" or "text_body".
# They are matched per camelCase/snake_case segment rather than as a bare
# substring, because a substring match would also deny "context" — ordinary
# audit metadata — while an exact match alone would let "messageText" through.
_DENIED_SEGMENT_NAMES = frozenset({"text", "body"})
_FIELD_NAME_TOKENS = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[0-9]+")


def _normalized_field_name(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).casefold())


def _field_name_segments(value: Any) -> set[str]:
    return {token.casefold() for token in _FIELD_NAME_TOKENS.findall(str(value))}


def _is_denied_field(value: Any) -> bool:
    normalized = _normalized_field_name(value)
    if normalized in _DENIED_FIELD_NAMES:
        return True
    if _field_name_segments(value) & _DENIED_SEGMENT_NAMES:
        return True
    return any(marker in normalized for marker in _DENIED_FIELD_MARKERS)


def _now(value: datetime | str | None = None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        parsed = value
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _iso_millis(value: datetime | str | None = None) -> str:
    return _now(value).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def scrub(value: Any) -> Any:
    if isinstance(value, list):
        return [scrub(item) for item in value]
    if isinstance(value, tuple):
        return tuple(scrub(item) for item in value)
    if not isinstance(value, Mapping):
        return value
    return {
        key: scrub(child)
        for key, child in value.items()
        if not _is_denied_field(key)
    }


class AuditStore:
    """Stores only actor/action/result metadata, never message or attachment content."""

    def __init__(self, store: Any, account_id: str):
        self.store = store
        self.account_id = account_id

    def append(
        self,
        event_type: str,
        actor: Mapping[str, Any],
        subject: Mapping[str, Any],
        correlation_id: str,
        occurred_at: datetime | str | None = None,
    ) -> None:
        self.purge(_now(occurred_at) - timedelta(days=30))
        self.store.database.execute(
            "INSERT INTO audit_events(event_type, actor_json, subject_json, correlation_id, occurred_at) VALUES (?, ?, ?, ?, ?)",
            (event_type, _json(scrub(actor)), _json(scrub(subject)), correlation_id, _iso_millis(occurred_at)),
        )

    def list(self) -> list[dict[str, Any]]:
        rows = self.store.database.execute(
            "SELECT event_type, actor_json, subject_json, correlation_id, occurred_at FROM audit_events ORDER BY audit_id"
        ).fetchall()
        return [
            {
                "eventType": row["event_type"], "actor": scrub(json.loads(row["actor_json"])),
                "subject": scrub(json.loads(row["subject_json"])), "correlationId": row["correlation_id"],
                "occurredAt": row["occurred_at"],
            }
            for row in rows
        ]

    def purge(self, before: datetime | str | None = None) -> int:
        cutoff = _now(before or (datetime.now(timezone.utc) - timedelta(days=30)))
        with self.store.transaction():
            return self.store.database.execute(
                "DELETE FROM audit_events WHERE audit_id IN (SELECT audit_id FROM audit_events WHERE occurred_at < ? ORDER BY audit_id LIMIT 1000)", (_iso_millis(cutoff),)
            ).rowcount
