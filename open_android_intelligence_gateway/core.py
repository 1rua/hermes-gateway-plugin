"""Independent Python Gateway Core for the Hermes host.

The module intentionally owns its SQLite connection and account directory.  It
does not import another host implementation or a legacy runtime.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import sqlite3
import struct
import threading
import uuid
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping
from urllib.parse import urlsplit, parse_qs

from .account_paths import (
    AccountPaths,
    account_paths,
    default_hermes_gateway_root,
    ensure_account_directories,
)
from .audit import AuditStore
from .contract_assets import CONTRACT_DIRECTORY_NAME, CONTRACT_ROOT_ENV
from .credentials import hash_password, verify_password


logger = logging.getLogger("open_android_intelligence_gateway.core")

WIRE_PROTOCOL = "2.1"
PROTOCOL_VERSION = {"major": 2, "minor": 1}

# One transport that wants committed events as they happen. The account id is
# the account the event belongs to, so a stream never has to guess it.
EventSink = Callable[[str, Mapping[str, Any]], None]


def canonical_device_key(value: Any) -> bool:
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_-]{43}", value) is None:
        return False
    try:
        raw = base64.urlsafe_b64decode(value + "=")
        return len(raw) == 32 and base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") == value
    except (ValueError, TypeError):
        return False


# Contract section 4 core schema digest: a domain-separated, name-sorted listing
# of each named schema document's raw byte digest. Hashing the checked-in bytes
# keeps the value reproducible in every language that can read the files, which
# is what lets the phone and the Gateway compare the same number.
CORE_SCHEMA_HASH_DOMAIN = "open-android-intelligence/v2/core-schema-hash"
CORE_SCHEMA_FILE_NAMES = (
    "attachment.schema.json",
    "conversation.schema.json",
    "device-request.schema.json",
    "envelope.schema.json",
    "event.schema.json",
    "negotiate.schema.json",
    "session.schema.json",
)

# The reserved `/new` invocation (contract §7.1). The catalog declares it with
# `acceptsArguments: false`, so only this exact text is the new-conversation
# command; `/new <anything>` stays ordinary text the Agent has to interpret.
NEW_CONVERSATION_COMMAND = "/new"

# ── Interactive command approval (contract §7.2) ────────────────────────────
# The choice vocabulary is the host's own: `tools.approval.resolve_gateway_approval`
# understands exactly these four, so the protocol never invents a second set.
APPROVAL_CHOICES = ("once", "session", "always", "deny")
# Terminal outcomes only the Gateway may produce: nobody answered in time, or
# nobody could be given the chance to answer.
APPROVAL_TERMINAL_DECISIONS = ("timeout", "withdrawn")
APPROVAL_DECISIONS = APPROVAL_CHOICES + APPROVAL_TERMINAL_DECISIONS
# The shared fixture fixes the option list at 1..4 entries; a host that offered
# more would publish a payload the phone cannot validate.
APPROVAL_MAX_OPTIONS = 4
APPROVAL_EVENT_REQUESTED = "conversation.approval.requested"
APPROVAL_EVENT_RESOLVED = "conversation.approval.resolved"
# Only a fallback for a payload that omits it: the host's own `approvals.timeout`
# is what actually decides, and the Gateway always sends the number it used.
APPROVAL_DEFAULT_TIMEOUT_SECONDS = 300
APPROVAL_CAPABILITY = "agent-approval-cards-v1"


def resolve_host_approval(session_key: str, choice: str, request_id: str | None = None) -> int | None:
    """Unblock the Agent thread waiting on one approval.

    Returns the number of host waits this call released, or `None` when this
    process cannot reach the host approval runtime at all. `None` is a fact the
    caller must surface: it is never the same as "resolved", and a Gateway that
    cannot reach the runtime must not advertise approval cards.
    """
    try:
        from tools.approval import resolve_gateway_approval
    except Exception:
        return None
    try:
        return int(resolve_gateway_approval(session_key, choice, request_id=request_id))
    except Exception as exc:  # pragma: no cover - host runtime detail
        logger.warning("[open_android] Host approval resolution failed: %s", exc)
        return None


def _public_approval(approval: Mapping[str, Any]) -> dict[str, Any]:
    """The part of one approval a client may be told (contract §7.2).

    `sessionKey` and the host's request id are persisted so a decision that
    arrives late — even after a host restart — can still be resolved, but they
    are the Gateway's own bookkeeping and never leave this process. Returning the
    stored row as-is would hand a client the identifiers it is explicitly not
    allowed to name, so the answer is projected rather than forwarded.

    Only fields the contract already publishes in the event payload are included:
    a client can act on the verdict without learning anything new about the host.
    """
    public: dict[str, Any] = {}
    for key in ("approvalId", "conversationId", "decision", "decidedAt"):
        value = approval.get(key)
        if value is not None:
            public[key] = value
    return public


# The exact six shared vector documents of contract section 16. The enumeration
# is closed: its `schemaName` set does not include the conversation-UI schemas,
# so `conversation-ui.json` stays a local suite and is not a conformance input.
SHARED_VECTOR_FILE_NAMES = (
    "request-signatures.json", "protocol-negotiation.json", "auth-sessions.json",
    "attachments.json", "sse-events.json", "device-requests.json",
)


class GatewayError(Exception):
    """A protocol or state-machine error with a stable code."""

    def __init__(self, code: str, details: Mapping[str, Any] | None = None):
        super().__init__(code)
        self.code = code
        self.details = dict(details or {})


class TransactionOutcomeUnknown(GatewayError):
    def __init__(self, details: Mapping[str, Any] | None = None):
        super().__init__("OUTCOME_UNKNOWN", details)


@dataclass(frozen=True)
class AttachmentPolicy:
    """Gateway attachment retention policy, independent of payload size/MIME."""

    attachment_ttl_seconds: int = 3600

    def __post_init__(self) -> None:
        if self.attachment_ttl_seconds <= 0:
            raise ValueError("attachment retention TTL must be positive")


DEFAULT_ATTACHMENT_POLICY = AttachmentPolicy()
MESSAGE_DISPATCH_LEASE_SECONDS = 300

_ATTACHMENT_PUBLIC_STATUS = {
    "created": "staged",
    "uploading": "staged",
    "verified": "uploaded",
    "delivered": "uploaded",
    "acknowledged": "uploaded",
    "failed": "failed",
    "expired": "expired",
    "deleted": "expired",
}


@dataclass(frozen=True, init=False)
class VerifiedRequestContext:
    account_id: str
    device_id: str
    session_id: str
    request_id: str
    correlation_id: str
    pairing_generation: int
    grant_revision: int
    negotiation_id: str | None
    installation_id: str | None

    def __init__(
        self, account_id: str | None = None, device_id: str | None = None,
        session_id: str | None = None, request_id: str | None = None,
        correlation_id: str | None = None, pairing_generation: int | None = None,
        grant_revision: int | None = None, negotiation_id: str | None = None,
        installation_id: str | None = None, **aliases: Any,
    ):
        def take(primary: Any, alias: str) -> Any:
            alternate = aliases.pop(alias, None)
            if primary is not None and alternate is not None:
                raise TypeError(f"duplicate context field: {alias}")
            return primary if primary is not None else alternate

        fields = {
            "account_id": take(account_id, "accountId"),
            "device_id": take(device_id, "deviceId"),
            "session_id": take(session_id, "sessionId"),
            "request_id": take(request_id, "requestId"),
            "correlation_id": take(correlation_id, "correlationId"),
            "pairing_generation": take(pairing_generation, "pairingGeneration"),
            "grant_revision": take(grant_revision, "grantRevision"),
            "negotiation_id": take(negotiation_id, "negotiationId"),
            "installation_id": take(installation_id, "installationId"),
        }
        if aliases:
            raise TypeError(f"unknown context fields: {sorted(aliases)}")
        for name in ("account_id", "device_id", "session_id", "request_id", "correlation_id"):
            if not isinstance(fields[name], str) or not fields[name]:
                raise ValueError(f"missing or invalid context field: {name}")
        for name in ("pairing_generation", "grant_revision"):
            if (
                not isinstance(fields[name], int) or isinstance(fields[name], bool)
                or fields[name] < 0
            ):
                raise ValueError(f"missing or invalid context field: {name}")
        for name in ("negotiation_id", "installation_id"):
            if fields[name] is not None and (not isinstance(fields[name], str) or not fields[name]):
                raise ValueError(f"invalid context field: {name}")
        for name, value in fields.items():
            object.__setattr__(self, name, value)

    @property
    def accountId(self) -> str:
        return self.account_id

    @property
    def deviceId(self) -> str:
        return self.device_id

    @property
    def sessionId(self) -> str:
        return self.session_id

    @property
    def requestId(self) -> str:
        return self.request_id

    @property
    def correlationId(self) -> str:
        return self.correlation_id

    @property
    def pairingGeneration(self) -> int:
        return self.pairing_generation

    @property
    def grantRevision(self) -> int:
        return self.grant_revision

    @property
    def negotiationId(self) -> str | None:
        return self.negotiation_id

    @property
    def installationId(self) -> str | None:
        return self.installation_id


@dataclass(frozen=True, init=False)
class VerifiedGatewayRequest:
    context: VerifiedRequestContext
    method: str
    target: str
    body: Any
    idempotency_key: str | None
    last_event_id: str | None
    now: datetime | str | None

    def __init__(self, context: VerifiedRequestContext, method: str, target: str, body: Any = None,
                 idempotency_key: str | None = None, last_event_id: str | None = None,
                 now: datetime | str | None = None, **aliases: Any):
        if not isinstance(context, VerifiedRequestContext):
            raise TypeError("GatewayCore accepts only VerifiedRequestContext")
        if not isinstance(method, str) or not isinstance(target, str):
            raise TypeError("verified request method and target must be strings")
        idempotency_alias = aliases.pop("idempotencyKey", None)
        last_event_alias = aliases.pop("lastEventId", None)
        if idempotency_key is not None and idempotency_alias is not None:
            raise TypeError("duplicate request field: idempotencyKey")
        if last_event_id is not None and last_event_alias is not None:
            raise TypeError("duplicate request field: lastEventId")
        if aliases:
            raise TypeError(f"unknown request fields: {sorted(aliases)}")
        object.__setattr__(self, "context", context)
        object.__setattr__(self, "method", method)
        object.__setattr__(self, "target", target)
        object.__setattr__(self, "body", _freeze(body))
        object.__setattr__(self, "idempotency_key", idempotency_key if idempotency_key is not None else idempotency_alias)
        object.__setattr__(self, "last_event_id", last_event_id if last_event_id is not None else last_event_alias)
        object.__setattr__(self, "now", now)

    @property
    def idempotencyKey(self) -> str | None:
        return self.idempotency_key

    @property
    def lastEventId(self) -> str | None:
        return self.last_event_id


class _FrozenDict(dict[str, Any]):
    def _readonly(self, *_: Any, **__: Any) -> None:
        raise TypeError("GatewayResponse is immutable")

    __setitem__ = _readonly
    __delitem__ = _readonly
    clear = _readonly
    pop = _readonly
    popitem = _readonly
    setdefault = _readonly
    update = _readonly
    __ior__ = _readonly


class _FrozenList(list[Any]):
    def _readonly(self, *_: Any, **__: Any) -> None:
        raise TypeError("GatewayResponse is immutable")

    __setitem__ = _readonly
    __delitem__ = _readonly
    __iadd__ = _readonly
    __imul__ = _readonly
    append = _readonly
    clear = _readonly
    extend = _readonly
    insert = _readonly
    pop = _readonly
    remove = _readonly
    reverse = _readonly
    sort = _readonly


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        frozen = _FrozenDict()
        dict.__init__(frozen, ((key, _freeze(child)) for key, child in value.items()))
        return frozen
    if isinstance(value, list):
        frozen = _FrozenList()
        list.__init__(frozen, (_freeze(child) for child in value))
        return frozen
    if isinstance(value, tuple):
        return _FrozenList(_freeze(child) for child in value)
    return value


class GatewayResponse(dict[str, Any]):
    def __init__(self, value: Mapping[str, Any] | None = None, **kwargs: Any):
        dict.__init__(self, _freeze(dict(value or {}, **kwargs)))

    def _readonly(self, *_: Any, **__: Any) -> None:
        raise TypeError("GatewayResponse is immutable")

    __setitem__ = _readonly
    __delitem__ = _readonly
    clear = _readonly
    pop = _readonly
    popitem = _readonly
    setdefault = _readonly
    update = _readonly
    __ior__ = _readonly
    @property
    def requestId(self) -> str:
        return str(self["requestId"])

    @property
    def request_id(self) -> str:
        return self.requestId

    @property
    def correlationId(self) -> str:
        return str(self["correlationId"])

    @property
    def correlation_id(self) -> str:
        return self.correlationId

    @property
    def protocol(self) -> str:
        return str(self["protocol"])

    @property
    def data(self) -> Mapping[str, Any] | None:
        return self.get("data")

    @property
    def error(self) -> Mapping[str, Any] | None:
        return self.get("error")


def _jcs(value: Any) -> str:
    """The contract fixtures use JSON values whose JCS form is this subset."""

    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _contract_root(explicit: str | Path | None = None) -> Path:
    candidates: list[Path] = []
    configured = os.environ.get(CONTRACT_ROOT_ENV, "").strip()
    # An explicit argument is the most authoritative source: a caller that
    # copied the contract to a temporary tree in order to exercise it must get
    # that tree even when the environment names a different one.
    if explicit is not None:
        given = Path(explicit).resolve()
        candidates.extend([given, given / CONTRACT_DIRECTORY_NAME])
    # Then the operator override: as a standalone plugin checkout the package no
    # longer sits inside the application repository, so the upward search below
    # has nothing to find and a configured directory is the only thing that can
    # supply the contract.
    if configured:
        given = Path(configured).expanduser()
        candidates.extend([given, given / CONTRACT_DIRECTORY_NAME])
    source = Path(__file__).resolve()
    candidates.extend(parent / CONTRACT_DIRECTORY_NAME for parent in source.parents)
    cwd = Path.cwd().resolve()
    candidates.extend(parent / CONTRACT_DIRECTORY_NAME for parent in (cwd, *cwd.parents))
    for candidate in candidates:
        if (candidate / "schemas" / "envelope.schema.json").is_file() and (candidate / "vectors" / "vector-set-1.0.0.schema.json").is_file():
            return candidate
    raise GatewayError("INTERNAL_ERROR", {"reason": "gateway-contract assets unavailable"})


def canonicalize_target(target: str) -> str:
    """Canonicalize the protocol origin-form target without URL normalization."""

    if not isinstance(target, str) or not target or target == "*" or "#" in target:
        raise GatewayError("SCHEMA_INVALID")
    if any(ord(char) <= 0x20 or ord(char) == 0x7F or ord(char) > 0x7F for char in target):
        raise GatewayError("SCHEMA_INVALID")
    if not target.startswith("/") or target.startswith("//"):
        raise GatewayError("SCHEMA_INVALID")
    path, separator, query = target.partition("?")
    if not path.startswith("/open-android-intelligence/v2") or (len(path) > len("/open-android-intelligence/v2") and not path.startswith("/open-android-intelligence/v2/")):
        raise GatewayError("SCHEMA_INVALID")

    def encoded_bytes(value: str) -> bytes:
        result = bytearray()
        index = 0
        while index < len(value):
            char = value[index]
            if char == "%":
                if index + 2 >= len(value) or not re.fullmatch(r"[0-9A-Fa-f]{2}", value[index + 1:index + 3]):
                    raise GatewayError("SCHEMA_INVALID")
                result.append(int(value[index + 1:index + 3], 16))
                index += 3
                continue
            result.extend(char.encode("ascii"))
            index += 1
        return bytes(result)

    def encode_component(value: str) -> str:
        raw = encoded_bytes(value)
        return "".join(chr(byte) if (65 <= byte <= 90 or 97 <= byte <= 122 or 48 <= byte <= 57 or byte in b"._~-") else f"%{byte:02X}" for byte in raw)

    segments = path.split("/")
    if any(segment == "" for segment in segments[1:]):
        raise GatewayError("SCHEMA_INVALID")
    canonical_segments: list[str] = []
    for segment in segments:
        decoded = encoded_bytes(segment)
        if decoded in (b".", b"..") or b"/" in decoded or b"\\" in decoded:
            raise GatewayError("SCHEMA_INVALID")
        canonical_segments.append(encode_component(segment))
    canonical_path = "/".join(canonical_segments)
    if separator == "" and query:
        raise GatewayError("SCHEMA_INVALID")
    if separator and not query:
        raise GatewayError("SCHEMA_INVALID")
    if not separator:
        return canonical_path
    pairs: list[tuple[str, str]] = []
    for item in query.split("&"):
        if not item:
            raise GatewayError("SCHEMA_INVALID")
        name, equals, value = item.partition("=")
        if not name:
            raise GatewayError("SCHEMA_INVALID")
        encoded_name = encode_component(name)
        encoded_value = encode_component(value if equals else "")
        pairs.append((encoded_name, encoded_value))
    pairs.sort(key=lambda pair: (pair[0].encode("ascii"), pair[1].encode("ascii")))
    return canonical_path + "?" + "&".join(f"{name}={value}" for name, value in pairs)


def request_signature_preimage(input: Mapping[str, Any]) -> bytes:
    method = input.get("method")
    if method not in {"GET", "POST", "PUT", "DELETE", "PATCH"}:
        raise GatewayError("SCHEMA_INVALID")
    target = input.get("target")
    canonical = canonicalize_target(target)
    if target != canonical:
        raise GatewayError("NON_CANONICAL_TARGET")
    body_hex = input.get("bodyHex")
    if not isinstance(body_hex, str) or re.fullmatch(r"(?:[0-9a-f]{2})*", body_hex) is None:
        raise GatewayError("SCHEMA_INVALID")
    return request_signature_preimage_from_digest(
        input, hashlib.sha256(bytes.fromhex(body_hex)).hexdigest(),
    )


def request_signature_preimage_from_digest(input: Mapping[str, Any], body_sha256: str) -> bytes:
    """Build the unchanged V2 signature preimage from a streamed-body digest."""
    method = input.get("method")
    if method not in {"GET", "POST", "PUT", "DELETE", "PATCH"}:
        raise GatewayError("SCHEMA_INVALID")
    target = input.get("target")
    canonical = canonicalize_target(target)
    if target != canonical:
        raise GatewayError("NON_CANONICAL_TARGET")
    if not isinstance(body_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", body_sha256) is None:
        raise GatewayError("SCHEMA_INVALID")
    fields = [
        "OPEN-ANDROID-INTELLIGENCE-REQUEST-V2", method, canonical, input.get("accountId"), input.get("deviceId"),
        input.get("sessionId"), input.get("requestId"), input.get("timestamp"), input.get("nonce"),
        body_sha256,
    ]
    if not all(isinstance(field, str) for field in fields):
        raise GatewayError("SCHEMA_INVALID")
    try:
        return "\n".join(fields).encode("ascii")
    except UnicodeEncodeError as exc:
        raise GatewayError("SCHEMA_INVALID") from exc


class ContractRegistry:
    """Read-only consumer of the repository's shared Schema and fixture registry."""

    dispatched_registry_id = "gateway-core-schemas-v1"

    schema_definitions = {
        "negotiate.request": ("negotiate.schema.json", "request"),
        "negotiate.response": ("negotiate.schema.json", "response"),
        "session.password": ("session.schema.json", "password"),
        "session.refresh": ("session.schema.json", "refresh"),
        "session.device": ("session.schema.json", "device"),
        "session.logout": ("session.schema.json", "logout"),
        "session.unpair": ("session.schema.json", "unpair"),
        "session.pairing": ("session.schema.json", "pairing"),
        "session.pairingSummary": ("session.schema.json", "pairingSummary"),
        "conversation.create": ("conversation.schema.json", "create"),
        "message.create": ("conversation.schema.json", "messageCreate"),
        "attachment.create": ("attachment.schema.json", "create"),
        "event": ("event.schema.json", "event"),
        "event.sessionRevokedPayload": ("event.schema.json", "sessionRevokedPayload"),
        "event.pairingGrantChangedPayload": ("event.schema.json", "pairingGrantChangedPayload"),
        "device.request": ("device-request.schema.json", "request"),
        "device.request.result": ("device-request.schema.json", "result"),
        "device.request.resultRequest": ("device-request.schema.json", "resultRequest"),
        "response.success": ("envelope.schema.json", "success"),
        "response.failure": ("envelope.schema.json", "failure"),
        "conversation.commandCatalog": ("conversation.schema.json", "commandCatalog"),
        "conversation.cancel": ("conversation.schema.json", "generationCancel"),
        "conversation.generationCancel": ("conversation.schema.json", "generationCancel"),
        "conversation.mirror": ("conversation.schema.json", "mirrorSync"),
        "conversation.mirrorSync": ("conversation.schema.json", "mirrorSync"),
        "attachment.status": ("attachment.schema.json", "status"),
    }

    @property
    def core_schema_hash(self) -> str:
        lines = [CORE_SCHEMA_HASH_DOMAIN]
        schema_dir = self.root / "schemas"
        for name in CORE_SCHEMA_FILE_NAMES:
            digest = hashlib.sha256((schema_dir / name).read_bytes()).hexdigest()
            lines.append(f"{name}\tsha256:{digest}")
        payload = "\n".join(lines) + "\n"
        return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def __init__(self, contract_root: str | Path | None = None):
        self.root = _contract_root(contract_root)
        schema_dir = self.root / "schemas"
        self.documents: dict[str, dict[str, Any]] = {}
        for path in schema_dir.glob("*.schema.json"):
            document = json.loads(path.read_text(encoding="utf-8"))
            self.documents[document["$id"]] = document
        self._catalog: dict[tuple[Any, ...], dict[str, Any]] = {}
        self._bindings: dict[str, dict[tuple[Any, ...], str]] = {}
        self._load_dispatched_registry()

    @staticmethod
    def _logical_key(key: Mapping[str, Any]) -> tuple[Any, ...]:
        return tuple((name, key[name]) for name in sorted(key) if name != "schemaSha256")

    def _load_dispatched_registry(self) -> None:
        def invalid(reason: str) -> None:
            raise GatewayError("DISPATCHED_REGISTRY_INVALID", {"reason": reason})

        try:
            registry_path = self.root / "core-dispatched-schemas.json"
            registry = json.loads(registry_path.read_text(encoding="utf-8"))
            if set(registry) != {"formatVersion","catalogEntries","bindings"}:
                invalid("unknown registry fields")
            if registry.get("formatVersion") != "1.0.0":
                invalid("unsupported registry format")
            catalog_entries = registry.get("catalogEntries")
            bindings = registry.get("bindings")
            if not isinstance(catalog_entries, list) or not isinstance(bindings, list):
                invalid("registry collections are not arrays")
            if any(e.get("key", {}).get("kind") == "device.request" for e in catalog_entries):
                invalid("device schemas must come from verified pairing bindings")

            catalog_keys: list[tuple[Any, ...]] = []
            catalog_by_key: dict[tuple[Any, ...], dict[str, Any]] = {}
            for entry in catalog_entries:
                if not isinstance(entry, Mapping) or set(entry) != {"key","schema"} or not isinstance(entry.get("key"), Mapping) or not isinstance(entry.get("schema"), Mapping):
                    invalid("catalog entry shape invalid")
                key = self._logical_key(entry["key"])
                if key in catalog_by_key:
                    invalid("duplicate catalog logical key")
                expected = entry["key"].get("schemaSha256")
                actual = "sha256:" + hashlib.sha256(_jcs(entry["schema"]).encode("utf-8")).hexdigest()
                if expected != actual:
                    invalid("catalog schema digest mismatch")
                catalog_keys.append(key)
                catalog_by_key[key] = {"schemaSha256": expected, "schema": entry["schema"]}

            binding_map: dict[tuple[Any, ...], str] = {}
            binding_keys: list[tuple[Any, ...]] = []
            for binding in bindings:
                if not isinstance(binding, Mapping) or set(binding) != {"key","schemaSha256"} or not isinstance(binding.get("key"), Mapping):
                    invalid("binding shape invalid")
                key = self._logical_key(binding["key"])
                if key in binding_map:
                    invalid("duplicate binding logical key")
                if key not in catalog_by_key:
                    invalid("binding points to missing catalog entry")
                digest = binding.get("schemaSha256")
                if catalog_by_key[key]["schemaSha256"] != digest:
                    invalid("binding digest mismatch")
                binding_keys.append(key)
                binding_map[key] = digest
            if binding_keys != catalog_keys:
                invalid("binding order or logical key mismatch")
            self._catalog = catalog_by_key
            self._bindings[self.dispatched_registry_id] = binding_map
        except GatewayError as exc:
            if exc.code == "DISPATCHED_REGISTRY_INVALID":
                raise
            invalid("registry validation failed")
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            invalid(f"registry parsing failed: {type(exc).__name__}")

    def _resolve_ref(self, ref: str, current_document: Mapping[str, Any]) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
        if ref.startswith("#/$defs/"):
            document = current_document
            name = ref[len("#/$defs/"):]
        else:
            marker = "#/$defs/"
            if marker not in ref:
                raise GatewayError("SCHEMA_INVALID")
            document_id, name = ref.split(marker, 1)
            document = self.documents.get(document_id)
            if document is None:
                raise GatewayError("SCHEMA_INVALID")
        definition = document.get("$defs", {}).get(name)
        if not isinstance(definition, Mapping):
            raise GatewayError("SCHEMA_INVALID")
        return document, definition

    def _valid(self, schema: Any, value: Any, current_document: Mapping[str, Any]) -> bool:
        if schema is True:
            return True
        if schema is False or not isinstance(schema, Mapping):
            return False
        if "$ref" in schema:
            document, resolved = self._resolve_ref(str(schema["$ref"]), current_document)
            return self._valid(resolved, value, document)
        if "const" in schema and value != schema["const"]:
            return False
        if "enum" in schema and value not in schema["enum"]:
            return False
        if "not" in schema and self._valid(schema["not"], value, current_document):
            return False
        if "allOf" in schema and not all(self._valid(child, value, current_document) for child in schema["allOf"]):
            return False
        if "anyOf" in schema and not any(self._valid(child, value, current_document) for child in schema["anyOf"]):
            return False
        if "oneOf" in schema and sum(self._valid(child, value, current_document) for child in schema["oneOf"]) != 1:
            return False
        schema_type = schema.get("type")
        if schema_type == "object":
            if not isinstance(value, Mapping):
                return False
        elif schema_type == "array":
            if not isinstance(value, list):
                return False
        elif schema_type == "string":
            if not isinstance(value, str):
                return False
        elif schema_type == "integer":
            if not isinstance(value, int) or isinstance(value, bool):
                return False
        elif schema_type == "number":
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                return False
        elif schema_type == "boolean" and not isinstance(value, bool):
            return False
        elif schema_type == "null" and value is not None:
            return False
        if isinstance(value, str):
            if len(value) < int(schema.get("minLength", 0)) or ("maxLength" in schema and len(value) > int(schema["maxLength"])):
                return False
            pattern = schema.get("pattern")
            if pattern is not None and re.fullmatch(str(pattern), value) is None:
                return False
            if schema.get("format") == "date-time":
                try:
                    datetime.fromisoformat(value.replace("Z", "+00:00"))
                except ValueError:
                    return False
        if isinstance(value, (int, float)) and "minimum" in schema and value < schema["minimum"]:
            return False
        if isinstance(value, list):
            if len(value) < int(schema.get("minItems", 0)):
                return False
            if schema.get("uniqueItems") and len({_jcs(item) for item in value}) != len(value):
                return False
            if "items" in schema and not all(self._valid(schema["items"], item, current_document) for item in value):
                return False
        if isinstance(value, Mapping):
            required = schema.get("required", [])
            if any(key not in value for key in required):
                return False
            properties = schema.get("properties", {})
            if schema.get("additionalProperties") is False and any(key not in properties for key in value):
                return False
            for key, child in properties.items():
                if key in value and not self._valid(child, value[key], current_document):
                    return False
            additional = schema.get("additionalProperties")
            if isinstance(additional, Mapping):
                if any(key not in properties and not self._valid(additional, child, current_document) for key, child in value.items()):
                    return False
        return True

    def validate(self, name: str, value: Any) -> bool:
        target = self.schema_definitions.get(name)
        if target is None:
            raise GatewayError("SCHEMA_INVALID")
        document = self.documents.get(next((doc_id for doc_id, doc in self.documents.items() if doc_id.endswith(target[0])), ""))
        if document is None:
            raise GatewayError("INTERNAL_ERROR", {"reason": f"missing schema document: {target[0]}"})
        return self._valid(document["$defs"][target[1]], value, document)

    def validate_dispatched(self, binding_set_id: str, dispatch: Mapping[str, Any], value: Any) -> bool:
        if not isinstance(dispatch, Mapping) or binding_set_id != self.dispatched_registry_id:
            return False
        kind = dispatch.get("kind")
        if kind == "event":
            if set(dispatch) != {"kind", "eventType"}:
                return False
            if not self.validate("event", value):
                return False
            logical = (('eventType', dispatch.get("eventType")), ('kind', "event"))
            payload = value.get("payload") if isinstance(value, Mapping) else None
        elif kind == "device.request":
            if set(dispatch) != {"kind"}:
                return False
            if not self.validate("device.request", value):
                return False
            provider = value.get("provider", {})
            capability = value.get("capability", {})
            logical = (('authorKeyId', provider.get("authorKeyId")), ('capabilityId', capability.get("id")), ('capabilityVersion', capability.get("version")), ('kind', "device.request"), ('pluginId', provider.get("pluginId")))
            payload = value.get("parameters")
        elif kind == "response.success":
            if set(dispatch) != {"kind", "operation", "status"}:
                return False
            if not self.validate("response.success", value):
                return False
            logical = (('kind', "response.success"), ('operation', dispatch.get("operation")), ('status', dispatch.get("status")))
            payload = value.get("data") if isinstance(value, Mapping) else None
        elif kind == "response.failure":
            if set(dispatch) != {"kind"}:
                return False
            if not self.validate("response.failure", value):
                return False
            error = value.get("error", {})
            logical = (('errorCode', error.get("code")), ('kind', "response.failure"))
            payload = error.get("details") if isinstance(error, Mapping) else None
        else:
            return False
        schema = self._bindings[self.dispatched_registry_id].get(logical)
        if schema is None:
            return False
        entry = self._catalog.get(logical)
        if entry is not None and entry["schemaSha256"] != schema:
            entry = None
        return entry is not None and self._valid(entry["schema"], payload, self.documents[next(iter(self.documents))])


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


def iso_millis(value: datetime | str | None = None) -> str:
    return _now(value).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _epoch_millis(value: datetime | str | None = None) -> int:
    if value is None:
        return 0
    if isinstance(value, (int, float)):
        return int(value)
    try:
        dt = _now(value)
        return int(dt.timestamp() * 1000)
    except Exception:
        try:
            text = str(value).replace("Z", "+00:00")
            dt = datetime.fromisoformat(text)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp() * 1000)
        except Exception:
            return 0


def _json(value: Any) -> str:
    def encode(child: Any) -> Any:
        if isinstance(child, (bytes, bytearray, memoryview)):
            return {"bytesSha256": hashlib.sha256(bytes(child)).hexdigest()}
        if isinstance(child, StreamedAttachmentUpload):
            return {"bytesSha256": child.sha256}
        if isinstance(child, Mapping):
            return {str(key): encode(item) for key, item in child.items()}
        if isinstance(child, (list, tuple)):
            return [encode(item) for item in child]
        return child

    encoded = encode(value)
    return json.dumps(encoded, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _hash_input(method: str, target: str, body: Any) -> str:
    return hashlib.sha256(_json({"method": method, "target": target, "body": body}).encode("utf-8")).hexdigest()


def _digest_prefix(value: Any) -> str:
    """`sha256:` plus the first eight hex digits, or a marker when it is absent.

    Truncating is safe without a shape re-check: every caller runs after
    `negotiate.request` validation, which already pins this field to `sha256:`
    plus 64 lowercase hex digits. A missing value still has to be named, because
    "the client sent nothing" is exactly what an operator needs to see.
    """
    if not isinstance(value, str) or not value:
        return "<missing>"
    return value[:15]


def _negotiation_client_hint(body: Any, expected_core: str) -> str:
    """Names the client build and both core digests of one refused negotiation.

    A refused negotiation stops before authentication, so no session, audit row
    or event ever records it: this string is the only trace a version mismatch
    leaves behind. It must therefore answer "which side is stale?" on its own.
    Digests are public contract hashes, never secrets, and only prefixes are
    reported. Nothing here may raise: it runs on the failure path.
    """
    client = body.get("client") if isinstance(body, Mapping) else None
    client = client if isinstance(client, Mapping) else {}
    hashes = body.get("schemaHashes") if isinstance(body, Mapping) else None
    hashes = hashes if isinstance(hashes, Mapping) else {}
    return (
        f"installationId={client.get('installationId', '<missing>')} "
        f"appVersion={client.get('appVersion', '<missing>')} "
        f"clientCore={_digest_prefix(hashes.get('core'))} "
        f"gatewayCore={_digest_prefix(expected_core)}"
    )


def _negotiation_binding_reason(
    row: Any, context: Mapping[str, Any], installation_id: str,
) -> str:
    """Why one negotiation binding was refused, in the operator's words.

    `no binding recorded` is the answer for a negotiation the pre-auth step never
    completed, or one whose row was reaped. The others name the single field that
    disagrees, which is the difference between a phone that needs to negotiate
    again and an id being replayed from somewhere else.

    Callers only reach this once they have already decided the binding is unusable,
    so a row that matches on every field it can name is the expired one; no clock
    is passed in because nothing here has to re-judge the window.
    """
    if row is None:
        return "no binding recorded"
    if row["account_id"] != context["accountId"]:
        return "bound to another account"
    if row["installation_id"] != installation_id:
        return "bound to another installation"
    return "expired"


def _value(value: Any, *names: str, default: Any = None) -> Any:
    for name in names:
        if isinstance(value, Mapping) and name in value:
            return value[name]
        if hasattr(value, name):
            return getattr(value, name)
    return default


def _context_value(context: Any, camel: str, snake: str, default: Any = None) -> Any:
    return _value(context, camel, snake, default=default)


def _request_context(request: Any) -> dict[str, Any]:
    context = _value(request, "context")
    if not isinstance(context, VerifiedRequestContext):
        raise GatewayError("AUTHENTICATION_REQUIRED")
    result = {
        "accountId": context.accountId,
        "deviceId": context.deviceId,
        "sessionId": context.sessionId,
        "requestId": context.requestId,
        "correlationId": context.correlationId,
        "pairingGeneration": context.pairingGeneration,
        "grantRevision": context.grantRevision,
    }
    negotiation_id = context.negotiationId
    installation_id = context.installationId
    if negotiation_id is not None:
        result["negotiationId"] = negotiation_id
    if installation_id is not None:
        result["installationId"] = installation_id
    return result


def _request_body(request: Any) -> Any:
    return _value(request, "body", default=None)


def _request_headers(request: Any) -> dict[str, str]:
    """Case-folded headers of a pre-auth request, last value winning per name."""
    headers = _value(request, "headers")
    if headers is None:
        return {}
    if not isinstance(headers, Mapping):
        return {}
    return {str(name).lower(): str(value) for name, value in headers.items()}


def _bearer_token(headers: Mapping[str, str]) -> str | None:
    authorization = headers.get("authorization")
    if not isinstance(authorization, str):
        return None
    scheme, separator, token = authorization.partition(" ")
    if not separator or scheme.strip().lower() != "bearer":
        return None
    token = token.strip()
    return token or None


def _query_value(target: Any, name: str) -> str | None:
    if not isinstance(target, str):
        return None
    query = target.partition("?")[2]
    for item in query.split("&") if query else []:
        key, equals, value = item.partition("=")
        if key == name and equals:
            return value
    return None


def _query_flag(target: Any, name: str) -> bool:
    return (_query_value(target, name) or "").strip().lower() == "true"


def _request_now(request: Any) -> datetime:
    return _now(_value(request, "now", default=None))


def _success(context: Mapping[str, Any], data: Mapping[str, Any]) -> GatewayResponse:
    return GatewayResponse({
        "requestId": context["requestId"],
        "correlationId": context["correlationId"],
        "protocol": WIRE_PROTOCOL,
        "data": dict(data),
    })


def _failure(context: Mapping[str, Any], code: str, details: Mapping[str, Any] | None = None) -> GatewayResponse:
    return GatewayResponse({
        "requestId": context["requestId"],
        "correlationId": context["correlationId"],
        "protocol": WIRE_PROTOCOL,
        "error": {
            "code": code,
            "message": code,
            "retryable": code == "ATTACHMENT_STORAGE_UNAVAILABLE",
            "retryAfterSeconds": None,
            "details": dict(details or {}),
        },
    })


class AccountStore:
    """One SQLite connection for one already-resolved account directory."""

    def __init__(
        self, paths: AccountPaths, master_key_ref: str | None = None,
        commit_hook: Any = None, aead: Any = None,
        account_id: str | None = None, event_sink: EventSink | None = None,
    ):
        self.paths = paths
        self.master_key_ref = str(master_key_ref or "")
        self.commit_hook = commit_hook
        self.aead = aead
        self.account_id = str(account_id or "")
        self.event_sink = event_sink
        self._pending_events: list[dict[str, Any]] = []
        self.fail_next_commit = False
        ensure_account_directories(paths)
        self.database = sqlite3.connect(str(paths.database), isolation_level=None, check_same_thread=False)
        self.database.row_factory = sqlite3.Row
        self.database.execute("PRAGMA journal_mode = WAL")
        self.database.execute("PRAGMA foreign_keys = ON")
        self._transaction_depth = 0
        self.database.executescript(
            """
            CREATE TABLE IF NOT EXISTS account_metadata (
              key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS refresh_credentials (
              credential_hash TEXT PRIMARY KEY NOT NULL,
              installation_id TEXT NOT NULL, device_id TEXT NOT NULL,
              session_id TEXT NOT NULL, status TEXT NOT NULL,
              created_at TEXT NOT NULL, replaced_by_hash TEXT
            );
            CREATE TABLE IF NOT EXISTS access_sessions (
              session_id TEXT PRIMARY KEY NOT NULL,
              installation_id TEXT NOT NULL, device_id TEXT NOT NULL,
              access_token_hash TEXT, status TEXT NOT NULL,
              created_at TEXT NOT NULL, expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS device_keys (
              device_id TEXT PRIMARY KEY NOT NULL,
              installation_id TEXT NOT NULL, public_key TEXT NOT NULL,
              pairing_generation INTEGER NOT NULL DEFAULT 1,
              grant_revision INTEGER NOT NULL DEFAULT 1,
              registered_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS idempotency_ledger (
              device_id TEXT NOT NULL, request_id TEXT NOT NULL,
              input_hash TEXT NOT NULL, outcome_json TEXT NOT NULL,
              expires_at TEXT NOT NULL,
              PRIMARY KEY (device_id, request_id)
            );
            CREATE TABLE IF NOT EXISTS events (
              sequence INTEGER PRIMARY KEY AUTOINCREMENT,
              event_id TEXT UNIQUE NOT NULL, event_type TEXT NOT NULL,
              correlation_id TEXT NOT NULL, occurred_at TEXT NOT NULL,
              payload_json TEXT NOT NULL, expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS attachments (
              attachment_id TEXT PRIMARY KEY NOT NULL,
              client_attachment_id TEXT NOT NULL, owner_device_id TEXT,
              owner_pairing_generation INTEGER, storage_revision INTEGER NOT NULL DEFAULT 0,
              filename TEXT NOT NULL,
              media_type TEXT NOT NULL, size_bytes INTEGER NOT NULL,
              sha256 TEXT NOT NULL, state TEXT NOT NULL,
              content_path TEXT, cas_path TEXT, created_at TEXT NOT NULL,
              expires_at TEXT NOT NULL, delivered_at TEXT,
              acknowledged_at TEXT
            );
            CREATE TABLE IF NOT EXISTS conversations (
              conversation_id TEXT PRIMARY KEY NOT NULL,
              client_conversation_id TEXT NOT NULL, title TEXT,
              created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS messages (
              message_id TEXT PRIMARY KEY NOT NULL,
              conversation_id TEXT NOT NULL, client_message_id TEXT NOT NULL,
              sender TEXT NOT NULL DEFAULT 'user',
              text TEXT NOT NULL DEFAULT '',
              created_at TEXT NOT NULL, attachment_ids_json TEXT NOT NULL,
              state TEXT NOT NULL DEFAULT 'CONFIRMED',
              FOREIGN KEY (conversation_id) REFERENCES conversations(conversation_id)
            );
            CREATE TABLE IF NOT EXISTS conversation_message_dispatch (
              message_id TEXT PRIMARY KEY NOT NULL,
              conversation_id TEXT NOT NULL,
              client_message_id TEXT NOT NULL,
              request_id TEXT NOT NULL,
              status TEXT NOT NULL,
              revision INTEGER NOT NULL,
              error_code TEXT,
              claim_token TEXT,
              claim_until TEXT,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              FOREIGN KEY (message_id) REFERENCES messages(message_id)
            );
            CREATE INDEX IF NOT EXISTS conversation_message_dispatch_status_idx
              ON conversation_message_dispatch(status, updated_at);
            CREATE TABLE IF NOT EXISTS conversation_agent_sessions (
              conversation_id TEXT PRIMARY KEY NOT NULL,
              agent_session_id TEXT, session_key TEXT,
              created_at TEXT NOT NULL, created_via TEXT NOT NULL,
              request_id TEXT,
              FOREIGN KEY (conversation_id) REFERENCES conversations(conversation_id)
            );
            CREATE TABLE IF NOT EXISTS device_requests (
              request_id TEXT PRIMARY KEY NOT NULL, device_id TEXT NOT NULL,
              pairing_generation INTEGER NOT NULL, grant_revision INTEGER NOT NULL,
              risk TEXT NOT NULL, state TEXT NOT NULL,
              capability_json TEXT NOT NULL, provider_json TEXT NOT NULL,
              parameters_json TEXT NOT NULL, created_at TEXT NOT NULL,
              expires_at TEXT NOT NULL, requires_foreground_confirmation INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS claim_receipts (
              claim_id TEXT PRIMARY KEY NOT NULL, request_id TEXT NOT NULL UNIQUE,
              device_id TEXT NOT NULL, pairing_generation INTEGER NOT NULL,
              grant_revision INTEGER NOT NULL, created_at TEXT NOT NULL,
              FOREIGN KEY (request_id) REFERENCES device_requests(request_id)
            );
            CREATE TABLE IF NOT EXISTS audit_events (
              audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
              event_type TEXT NOT NULL, actor_json TEXT NOT NULL,
              subject_json TEXT NOT NULL, correlation_id TEXT NOT NULL,
              occurred_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS identity_rotation_receipts (
              receipt_id TEXT PRIMARY KEY NOT NULL,
              previous_identity_ref TEXT NOT NULL, next_identity_ref TEXT NOT NULL,
              proof_hash TEXT NOT NULL, master_key_ref TEXT NOT NULL,
              rotated_at TEXT NOT NULL, correlation_id TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS plugin_registry (
              plugin_id TEXT PRIMARY KEY NOT NULL, manifest_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS account_credentials (
              credential_id TEXT PRIMARY KEY NOT NULL,
              password_hash TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS negotiations (
              negotiation_id TEXT PRIMARY KEY NOT NULL, response_json TEXT NOT NULL,
              created_at TEXT NOT NULL, expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS negotiation_bindings (
              negotiation_id TEXT PRIMARY KEY NOT NULL, account_id TEXT NOT NULL,
              installation_id TEXT NOT NULL, bound_at TEXT NOT NULL,
              expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS uncertain_outcomes (
              device_id TEXT NOT NULL, request_id TEXT NOT NULL,
              input_hash TEXT NOT NULL, created_at TEXT NOT NULL,
              expires_at TEXT NOT NULL,
              PRIMARY KEY (device_id, request_id)
            );
            CREATE TABLE IF NOT EXISTS approvals (
              approval_id TEXT PRIMARY KEY NOT NULL,
              conversation_id TEXT NOT NULL,
              session_key TEXT, host_request_id TEXT,
              command TEXT NOT NULL, reason TEXT NOT NULL, severity TEXT,
              options_json TEXT NOT NULL,
              timeout_seconds INTEGER NOT NULL,
              requested_at TEXT NOT NULL, expires_at TEXT NOT NULL,
              decision TEXT, decided_at TEXT, decided_by_device_id TEXT,
              created_at TEXT NOT NULL
            );
            """
        )
        existing_cols = {row[1] for row in self.database.execute("PRAGMA table_info(messages)").fetchall()}
        for col_name, col_type in [
            ("sender", "TEXT NOT NULL DEFAULT 'user'"),
            ("text", "TEXT NOT NULL DEFAULT ''"),
            ("state", "TEXT NOT NULL DEFAULT 'CONFIRMED'"),
        ]:
            if col_name not in existing_cols:
                self.database.execute(f"ALTER TABLE messages ADD COLUMN {col_name} {col_type}")
        self.database.executescript("""
            INSERT OR IGNORE INTO account_metadata(key, value)
              SELECT 'conversation_revision:' || conversation_id,
                CAST(1 + (SELECT COUNT(*) FROM messages m WHERE m.conversation_id = conversations.conversation_id) AS TEXT)
              FROM conversations;
            CREATE TRIGGER IF NOT EXISTS conversation_revision_created AFTER INSERT ON conversations
              BEGIN INSERT OR IGNORE INTO account_metadata(key,value)
                VALUES ('conversation_revision:' || NEW.conversation_id, '1'); END;
            CREATE TRIGGER IF NOT EXISTS conversation_revision_title AFTER UPDATE OF title ON conversations
              WHEN OLD.title IS NOT NEW.title
              BEGIN UPDATE account_metadata SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT)
                WHERE key = 'conversation_revision:' || NEW.conversation_id; END;
            CREATE TRIGGER IF NOT EXISTS conversation_revision_insert AFTER INSERT ON messages
              BEGIN UPDATE account_metadata SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT)
                WHERE key = 'conversation_revision:' || NEW.conversation_id; END;
            CREATE TRIGGER IF NOT EXISTS conversation_revision_update AFTER UPDATE ON messages
              BEGIN UPDATE account_metadata SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT)
                WHERE key = 'conversation_revision:' || NEW.conversation_id; END;
            CREATE TRIGGER IF NOT EXISTS conversation_revision_delete AFTER DELETE ON messages
              BEGIN UPDATE account_metadata SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT)
                WHERE key = 'conversation_revision:' || OLD.conversation_id; END;
            CREATE INDEX IF NOT EXISTS conversation_message_page
              ON messages(conversation_id, created_at, message_id);
        """)
        self.database.execute("BEGIN IMMEDIATE")
        try:
            event_columns = {row[1] for row in self.database.execute("PRAGMA table_info(events)").fetchall()}
            if "sequence" not in event_columns:
                self.database.execute("ALTER TABLE events RENAME TO events_legacy_order")
                self.database.execute("CREATE TABLE events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE NOT NULL, event_type TEXT NOT NULL, correlation_id TEXT NOT NULL, occurred_at TEXT NOT NULL, payload_json TEXT NOT NULL, expires_at TEXT NOT NULL)")
                # Preserve old row insertion order, ciphertext and opaque IDs.
                self.database.execute("INSERT INTO events(event_id,event_type,correlation_id,occurred_at,payload_json,expires_at) SELECT event_id,event_type,correlation_id,occurred_at,payload_json,expires_at FROM events_legacy_order ORDER BY rowid")
                self.database.execute("DROP TABLE events_legacy_order")
            self.database.execute("CREATE INDEX IF NOT EXISTS events_expiry ON events(expires_at)")
            if "result_json" not in {row["name"] for row in self.database.execute("PRAGMA table_info(device_requests)")}:
                self.database.execute("ALTER TABLE device_requests ADD COLUMN result_json TEXT NOT NULL DEFAULT ''")
            existing_attachment_cols = {
                row[1] for row in self.database.execute("PRAGMA table_info(attachments)").fetchall()
            }
            for col_name, col_type in (
                ("owner_device_id", "TEXT"),
                ("owner_pairing_generation", "INTEGER"),
                ("storage_revision", "INTEGER NOT NULL DEFAULT 0"),
            ):
                if col_name not in existing_attachment_cols:
                    self.database.execute(f"ALTER TABLE attachments ADD COLUMN {col_name} {col_type}")
            self._metadata("attachment_storage_format", "2")
            attachment_format = self.database.execute(
                "SELECT value FROM account_metadata WHERE key = 'attachment_storage_format'"
            ).fetchone()
            if attachment_format is None or str(attachment_format[0]) != "2":
                raise GatewayError("ATTACHMENT_STORAGE_VERSION_UNSUPPORTED")
            self.database.execute(
                """
                CREATE TRIGGER IF NOT EXISTS attachments_require_pairing_identity
                BEFORE INSERT ON attachments
                WHEN (SELECT value FROM account_metadata WHERE key = 'attachment_storage_format') = '2'
                  AND (NEW.owner_device_id IS NULL OR NEW.owner_device_id = '' OR NEW.owner_pairing_generation IS NULL)
                BEGIN
                  SELECT RAISE(ABORT, 'ATTACHMENT_PAIRING_BINDING_REQUIRED');
                END
                """
            )
            self.database.execute(
                """
                CREATE TRIGGER IF NOT EXISTS attachments_require_storage_revision
                BEFORE UPDATE ON attachments
                WHEN (SELECT value FROM account_metadata WHERE key = 'attachment_storage_format') = '2'
                  AND NEW.storage_revision != OLD.storage_revision + 1
                BEGIN
                  SELECT RAISE(ABORT, 'ATTACHMENT_STORAGE_VERSION_UNSUPPORTED');
                END
                """
            )
            self.database.execute("COMMIT")
        except BaseException:
            try:
                self.database.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            self.database.close()
            raise
        if self.aead is None:
            existing_ref = self.database.execute(
                "SELECT value FROM account_metadata WHERE key = 'master_key_ref'"
            ).fetchone()
            if existing_ref is None or not existing_ref[0] or str(existing_ref[0]).startswith("host-secret:"):
                self.database.execute(
                    "INSERT INTO account_metadata(key, value) VALUES ('master_key_ref', '') "
                    "ON CONFLICT(key) DO UPDATE SET value = ''"
                )
        else:
            existing_ref = self.database.execute(
                "SELECT value FROM account_metadata WHERE key = 'master_key_ref'"
            ).fetchone()
            if (
                existing_ref is not None
                and existing_ref[0]
                and not str(existing_ref[0]).startswith("host-secret:")
                and str(existing_ref[0]) != self.master_key_ref
            ):
                raise GatewayError("MASTER_KEY_REFERENCE_MISMATCH")
            self.database.execute(
                "INSERT INTO account_metadata(key, value) VALUES ('master_key_ref', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (self.master_key_ref,),
            )
        self._metadata("gateway_identity_ref", "spki_initial")
        self._metadata("pairing_generation", "1")
        if self.account_id:
            self._metadata("gateway_account_id", self.account_id)
        self._metadata("deployment_id", f"deploy_{hashlib.sha256(str(paths.root.parent.parent).encode('utf-8')).hexdigest()[:16]}")
        self._metadata("tls_spki_sha256", "sha256:" + "0" * 64)
        self.database.execute("PRAGMA secure_delete = ON")
        message_format = self.database.execute("SELECT value FROM account_metadata WHERE key = 'message_storage_format'").fetchone()
        if message_format is not None and message_format[0] != "1":
            raise GatewayError("MESSAGE_STORAGE_VERSION_UNSUPPORTED")
        if self.aead is not None and message_format is None:
            self.database.execute("BEGIN IMMEDIATE")
            try:
                for row in self.database.execute("SELECT message_id,text FROM messages").fetchall():
                    self.database.execute("UPDATE messages SET text = ? WHERE message_id = ?", (self.seal_json(row["text"], f"message:{row['message_id']}:text"), row["message_id"]))
                self.database.execute("INSERT INTO account_metadata(key,value) VALUES ('message_storage_format','1')")
                self.database.execute("INSERT INTO account_metadata(key,value) VALUES ('message_scrub_pending','1')")
                self.database.execute("COMMIT")
            except BaseException:
                self.database.execute("ROLLBACK")
                raise
        if self.aead is not None and self.database.execute("SELECT 1 FROM account_metadata WHERE key = 'message_scrub_pending'").fetchone() is not None:
            try:
                def checkpoint():
                    if self.database.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] != 0:
                        raise GatewayError("MESSAGE_MIGRATION_BUSY")
                checkpoint()
                self.database.execute("VACUUM")
                checkpoint()
                self.database.execute("DELETE FROM account_metadata WHERE key = 'message_scrub_pending'")
            except BaseException:
                self.database.close()
                raise

    def _metadata(self, key: str, value: str) -> None:
        self.database.execute(
            "INSERT OR IGNORE INTO account_metadata(key, value) VALUES (?, ?)",
            (key, value),
        )

    def require_aead(self) -> Any:
        if self.aead is None:
            raise GatewayError("MASTER_KEY_UNAVAILABLE")
        return self.aead

    def seal_bytes(self, plaintext: bytes, purpose: str) -> str:
        provider = self.require_aead()
        try:
            ciphertext = provider.encrypt(bytes(plaintext), purpose.encode("utf-8"))
        except Exception as exc:
            raise GatewayError("ENCRYPTION_FAILED") from exc
        if not isinstance(ciphertext, (bytes, bytearray, memoryview)):
            raise GatewayError("ENCRYPTION_FAILED")
        encoded = base64.urlsafe_b64encode(bytes(ciphertext)).decode("ascii")
        return "aead-v1:" + encoded

    def open_bytes(self, sealed: str, purpose: str) -> bytes:
        provider = self.require_aead()
        if not isinstance(sealed, str) or not sealed.startswith("aead-v1:"):
            raise GatewayError("DECRYPTION_FAILED")
        try:
            ciphertext = base64.b64decode(sealed[8:], altchars=b"-_", validate=True)
            plaintext = provider.decrypt(ciphertext, purpose.encode("utf-8"))
        except Exception as exc:
            raise GatewayError("DECRYPTION_FAILED") from exc
        if not isinstance(plaintext, (bytes, bytearray, memoryview)):
            raise GatewayError("DECRYPTION_FAILED")
        return bytes(plaintext)

    def seal_json(self, value: Any, purpose: str) -> str:
        return self.seal_bytes(_json(value).encode("utf-8"), purpose)

    def open_json(self, sealed: str, purpose: str) -> Any:
        try:
            return json.loads(self.open_bytes(sealed, purpose).decode("utf-8"))
        except GatewayError:
            raise
        except (UnicodeDecodeError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise GatewayError("DECRYPTION_FAILED") from exc

    @contextmanager
    def transaction(self, unknown_marker: Mapping[str, Any] | None = None) -> Iterator[sqlite3.Connection]:
        nested = self._transaction_depth > 0
        if not nested:
            self.database.execute("BEGIN IMMEDIATE")
        self._transaction_depth += 1
        try:
            yield self.database
        except BaseException as exc:
            if not nested:
                try:
                    self.database.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                self._transaction_depth = 0
                # Rolled back: these events never happened, so nothing may be
                # delivered for them.
                self._pending_events.clear()
                if isinstance(exc, TransactionOutcomeUnknown):
                    self._reopen_after_unknown()
                    self._persist_uncertain_marker(unknown_marker)
            else:
                self._transaction_depth -= 1
            raise
        if nested:
            self._transaction_depth -= 1
            return
        try:
            if self.fail_next_commit:
                self.fail_next_commit = False
                raise sqlite3.OperationalError("injected commit failure")
            if self.commit_hook is not None:
                self.commit_hook()
            self.database.execute("COMMIT")
        except BaseException as exc:
            self._transaction_depth = 0
            # The commit outcome is unknown, so whether these events are durable
            # is unknown too: claiming delivery would tell the phone about a fact
            # it might not be able to read back.
            self._pending_events.clear()
            self._reopen_after_unknown()
            self._persist_uncertain_marker(unknown_marker)
            raise TransactionOutcomeUnknown({"reason": "transaction commit outcome unknown"}) from exc
        self._transaction_depth = 0
        self._flush_events()

    def record_event(self, event: Mapping[str, Any]) -> None:
        """Hand one appended event to the stream that owns this store.

        Inside a transaction the delivery waits for `COMMIT`: an event must never
        reach a live subscriber before it is durable, or a reconnect would replay
        a fact the phone was already told and could not re-read. Outside one the
        write is already committed, so there is nothing to wait for.
        """
        if self._transaction_depth == 0:
            self._deliver_events([dict(event)])
            return
        self._pending_events.append(dict(event))

    recordEvent = record_event

    def _flush_events(self) -> None:
        pending = self._pending_events
        self._pending_events = []
        self._deliver_events(pending)

    def _deliver_events(self, events: list[dict[str, Any]]) -> None:
        """Deliver committed events; a stream failure never fails the write."""
        sink = self.event_sink
        if sink is None or not events:
            return
        for event in events:
            try:
                sink(self.account_id, event)
            except Exception as exc:  # noqa: BLE001 - delivery is best effort
                logger.warning("[open_android] Event delivery failed: %s", exc)

    def close(self) -> None:
        self.database.close()

    def _reopen_after_unknown(self) -> None:
        try:
            self.database.rollback()
        except sqlite3.Error:
            pass
        try:
            self.database.close()
        except sqlite3.Error:
            pass
        replacement = AccountStore(
            self.paths, self.master_key_ref, self.commit_hook, self.aead,
            account_id=self.account_id, event_sink=self.event_sink,
        )
        self.database = replacement.database
        self._transaction_depth = 0

    def _persist_uncertain_marker(self, marker: Mapping[str, Any] | None) -> None:
        if marker is None:
            return
        self.database.execute(
            "INSERT OR REPLACE INTO uncertain_outcomes(device_id, request_id, input_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
            (
                marker["deviceId"], marker["requestId"], marker["inputHash"],
                marker["createdAt"], marker["expiresAt"],
            ),
        )


class CredentialStore:
    """The account password digest, stored beside the account it protects.

    Only a digest is kept: the Gateway can never read a password back, and an
    account without a recorded digest cannot be logged into at all.
    """

    PASSWORD_CREDENTIAL_ID = "password"

    def __init__(self, store: AccountStore):
        self.store = store

    def set_password(self, password: str, now: datetime | str | None = None) -> None:
        self._write_password(password, now, create_only=False)

    def create_password(self, password: str, now: datetime | str | None = None) -> None:
        self._write_password(password, now, create_only=True)

    def _write_password(self, password: str, now: datetime | str | None, *, create_only: bool) -> None:
        digest = hash_password(password)
        with self.store.transaction():
            exists = self.has_password()
            if exists and create_only:
                raise GatewayError("ACCOUNT_EXISTS")
            self.store.database.execute(
                "INSERT INTO account_credentials(credential_id, password_hash, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(credential_id) DO UPDATE SET "
                "password_hash = excluded.password_hash, updated_at = excluded.updated_at",
                (self.PASSWORD_CREDENTIAL_ID, digest, iso_millis(now)),
            )
            if exists:
                self.store.database.execute("UPDATE refresh_credentials SET status = 'revoked'")

    def has_password(self) -> bool:
        row = self.store.database.execute(
            "SELECT 1 FROM account_credentials WHERE credential_id = ?",
            (self.PASSWORD_CREDENTIAL_ID,),
        ).fetchone()
        return row is not None

    def password_digest(self) -> str | None:
        """Local snapshot used only by the session-issuing transaction."""
        row = self.store.database.execute(
            "SELECT password_hash FROM account_credentials WHERE credential_id = ?",
            (self.PASSWORD_CREDENTIAL_ID,),
        ).fetchone()
        return str(row[0]) if row is not None else None

    def verify_password(self, password: str) -> bool:
        row = self.store.database.execute(
            "SELECT password_hash FROM account_credentials WHERE credential_id = ?",
            (self.PASSWORD_CREDENTIAL_ID,),
        ).fetchone()
        if row is None:
            return False
        return verify_password(password, str(row[0]))

    setPassword = set_password
    createPassword = create_password
    hasPassword = has_password
    verifyPassword = verify_password


class EventStore:
    def __init__(self, store: AccountStore, contracts: "ContractRegistry | None", retention_seconds: int = 86_400):
        self.store = store
        # Mirror DeviceRequestStore: a caller that cannot supply the shared
        # registry still gets a real one, because fail-closed validation must
        # never silently degrade to "no validation".
        self.contracts = contracts or ContractRegistry()
        self.retention_seconds = retention_seconds

    def append(
        self,
        event_type: str,
        correlation_id: str,
        payload: Mapping[str, Any],
        now: datetime | str | None = None,
    ) -> dict[str, Any]:
        current = _now(now)
        event = {
            "eventId": f"evt_{uuid.uuid4()}",
            "eventType": event_type,
            "correlationId": correlation_id,
            "occurredAt": iso_millis(current),
            "payload": dict(payload),
            "expiresAt": iso_millis(current + timedelta(seconds=self.retention_seconds)),
        }
        if event_type == "device.requested" and isinstance(payload.get("expiresAt"), str):
            event["expiresAt"] = min(event["expiresAt"], payload["expiresAt"])
        # Fail closed (contract §9): every event payload must validate against
        # its dispatched sub-Schema, and an event type without a binding must be
        # rejected rather than silently delivered unvalidated.
        verified = self.contracts.validate_dispatched(
            self.contracts.dispatched_registry_id,
            {"kind": "event", "eventType": event_type},
            {
                "correlationId": correlation_id,
                "occurredAt": event["occurredAt"],
                "payload": dict(payload),
            },
        )
        if not verified:
            raise GatewayError(
                "SCHEMA_INVALID",
                {"reason": "event payload failed dispatched validation", "eventType": event_type},
            )
        self.purge_expired(current)
        self.store.database.execute(
            "INSERT INTO events(event_id, event_type, correlation_id, occurred_at, payload_json, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                event["eventId"], event_type, correlation_id, event["occurredAt"],
                self.store.seal_json(payload, f"event:{event['eventId']}:payload"), event["expiresAt"],
            ),
        )
        # Live delivery is decided by the store, not by whichever caller appended
        # the event: a durable event that only reaches the phone on reconnect is
        # how a command result the Agent already produced stays invisible.
        self.store.record_event(event)
        return event

    def release_device_request(self, request_id: str) -> None:
        rows = self.store.database.execute("SELECT event_id,payload_json FROM events WHERE event_type='device.requested'")
        for row in rows:
            purpose = f"event:{row['event_id']}:payload"
            payload = self.store.open_json(row["payload_json"], purpose)
            if payload.get("requestId") == request_id and "parameters" in payload:
                payload["parameters"] = {}
                self.store.database.execute("UPDATE events SET payload_json=? WHERE event_id=?", (self.store.seal_json(payload,purpose),row["event_id"]))

    def read_after(self, cursor: str | None, now: datetime | str | None = None) -> list[dict[str, Any]]:
        current = _now(now)
        self.purge_expired(current)
        current_iso = iso_millis(current)
        if cursor is not None:
            row = self.store.database.execute("SELECT expires_at FROM events WHERE event_id = ?", (cursor,)).fetchone()
            if row is None or _now(row["expires_at"]) <= current:
                raise GatewayError("CURSOR_EXPIRED")
            rows = self.store.database.execute(
                """
                SELECT * FROM events
                WHERE expires_at > ? AND sequence >
                  (SELECT sequence FROM events WHERE event_id = ?)
                ORDER BY sequence
                """,
                (current_iso, cursor),
            ).fetchall()
        else:
            rows = self.store.database.execute(
                "SELECT * FROM events WHERE expires_at > ? ORDER BY sequence", (current_iso,)
            ).fetchall()
        return [self._map(row) for row in rows]

    def purge_expired(self, now: datetime | str | None = None, limit: int = 1000) -> int:
        marker = self.store.database.execute("SELECT value FROM account_metadata WHERE key='event-body-policy-v2'").fetchone()
        legacy = self.store.database.execute("SELECT event_id,sequence,payload_json,expires_at FROM events WHERE event_type='device.requested' AND sequence>? ORDER BY sequence LIMIT ?",(int(marker[0]) if marker else 0,limit)).fetchall()
        for row in legacy:
            purpose = f"event:{row['event_id']}:payload"
            payload = self.store.open_json(row['payload_json'],purpose)
            request = self.store.database.execute("SELECT parameters_json FROM device_requests WHERE request_id=?",(str(payload.get('requestId')),)).fetchone()
            if request is None or request[0] == '': payload['parameters'] = {}
            expiry = min(_now(row['expires_at']),_now(payload.get('expiresAt',row['expires_at'])))
            self.store.database.execute("UPDATE events SET payload_json=?,expires_at=? WHERE event_id=?",(self.store.seal_json(payload,purpose),iso_millis(expiry),row['event_id']))
        if legacy: self.store.database.execute("INSERT OR REPLACE INTO account_metadata(key,value) VALUES ('event-body-policy-v2',?)",(str(legacy[-1]['sequence']),))
        return self.store.database.execute(
            "DELETE FROM events WHERE sequence IN (SELECT sequence FROM events WHERE expires_at <= ? ORDER BY expires_at LIMIT ?)",
            (iso_millis(now), limit),
        ).rowcount

    def _map(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "eventId": row["event_id"],
            "eventType": row["event_type"],
            "correlationId": row["correlation_id"],
            "occurredAt": row["occurred_at"],
            "payload": self.store.open_json(row["payload_json"], f"event:{row['event_id']}:payload"),
            "expiresAt": row["expires_at"],
        }

    readAfter = read_after


class AgentSessionBindings:
    """Which Agent session owns one conversation's memory (ADR 0043).

    The Agent host holds the long-lived conversation, so the binding between a
    Gateway conversation and the host's own session is a fact about this account
    rather than a per-connection guess. Recording it is what makes "switch the
    conversation" mean "switch the memory": a conversation created by `/new` owns
    a session of its own, and a conversation someone opens again lands back on the
    session it already had.

    `agent_session_id` stays NULL until the host reports one. A placeholder would
    be an invented fact, and the phone would then be routed to a session that does
    not exist.
    """

    # Where a binding row came from. The command entry is the only path that also
    # creates the Agent session up front; the others reuse or create lazily.
    CREATED_VIA_NEW_COMMAND = "new-command"
    CREATED_VIA_CONVERSATION_READ = "conversation-read"
    CREATED_VIA_INBOUND_MESSAGE = "inbound-message"

    def __init__(self, store: AccountStore):
        self.store = store

    def record(
        self, conversation_id: str, created_via: str,
        request_id: str | None = None, now: datetime | str | None = None,
    ) -> dict[str, Any]:
        """Record that this conversation exists and owes the host a session.

        Idempotent by primary key: re-recording the same conversation never
        replaces the session it already has.
        """
        current = iso_millis(_now(now))
        self.store.database.execute(
            """
            INSERT INTO conversation_agent_sessions(
              conversation_id, agent_session_id, session_key, created_at, created_via, request_id
            ) VALUES (?, NULL, NULL, ?, ?, ?)
            ON CONFLICT(conversation_id) DO NOTHING
            """,
            (conversation_id, current, created_via, request_id),
        )
        binding = self.lookup(conversation_id)
        return binding if binding is not None else {
            "conversationId": conversation_id, "agentSessionId": None,
            "sessionKey": None, "createdAt": current, "createdVia": created_via,
            "requestId": request_id,
        }

    record_binding = record

    def attach(
        self, conversation_id: str, agent_session_id: str, session_key: str | None = None,
    ) -> bool:
        """Fill in the host's session id for a conversation that already has a row.

        The first session a conversation is bound to is kept: contract §7.1 makes
        the binding a fact about the account, so a later, slower ensure (a message
        or a read that raced the command entry) must not re-point a conversation
        to a second Agent session. A host that reports a *different* session for an
        already-bound conversation is recorded as the divergence it is, rather
        than silently rewriting the row.
        """
        existing = self.lookup(conversation_id)
        if existing is None:
            return False
        bound = existing["agentSessionId"]
        if isinstance(bound, str) and bound:
            if bound != agent_session_id:
                logger.warning(
                    "[open_android] Conversation %s is bound to Agent session %s but the host reported %s",
                    conversation_id, bound, agent_session_id,
                )
            return False
        cursor = self.store.database.execute(
            """
            UPDATE conversation_agent_sessions SET agent_session_id = ?, session_key = ?
            WHERE conversation_id = ? AND agent_session_id IS NULL
            """,
            (agent_session_id, session_key, conversation_id),
        )
        return cursor.rowcount > 0

    def lookup(self, conversation_id: str) -> dict[str, Any] | None:
        row = self.store.database.execute(
            "SELECT * FROM conversation_agent_sessions WHERE conversation_id = ?", (conversation_id,)
        ).fetchone()
        return None if row is None else self._map(row)

    def list(self) -> list[dict[str, Any]]:
        rows = self.store.database.execute(
            "SELECT * FROM conversation_agent_sessions ORDER BY created_at, conversation_id"
        ).fetchall()
        return [self._map(row) for row in rows]

    def _map(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "conversationId": row["conversation_id"],
            "agentSessionId": row["agent_session_id"],
            "sessionKey": row["session_key"],
            "createdAt": row["created_at"],
            "createdVia": row["created_via"],
            "requestId": row["request_id"],
        }


class ApprovalRequests:
    """One pending command-execution approval and the outcome it ended with.

    An approval is a fact about the account, not about a connection: the phone
    may go away and come back, the host may restart, and the decision still has
    to land on the Agent thread that is blocked waiting for it. That is why the
    host's own identifiers (`session_key`, its `request_id`) are persisted here
    instead of being handed to the client: contract §7.2 gives the phone only the
    opaque `approvalId`, so no client can name — or resolve — a session of its
    choosing.

    `decision` stays NULL until something authoritative settles it, and the
    first writer wins: a second, different decision is a conflict, not an update.
    """

    def __init__(self, store: AccountStore):
        self.store = store

    def record(
        self,
        approval_id: str,
        conversation_id: str,
        command: str,
        reason: str,
        options: list[dict[str, Any]],
        timeout_seconds: int,
        *,
        session_key: str | None = None,
        host_request_id: str | None = None,
        severity: str | None = None,
        requested_at: datetime | str | None = None,
        now: datetime | str | None = None,
    ) -> dict[str, Any]:
        """Persist one approval request. Idempotent by primary key."""
        current = _now(now or requested_at)
        requested = _now(requested_at)
        timeout = max(1, int(timeout_seconds))
        self.store.database.execute(
            """
            INSERT INTO approvals(
              approval_id, conversation_id, session_key, host_request_id,
              command, reason, severity, options_json,
              timeout_seconds, requested_at, expires_at,
              decision, decided_at, decided_by_device_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?)
            ON CONFLICT(approval_id) DO NOTHING
            """,
            (
                approval_id, conversation_id, session_key, host_request_id,
                str(command or ""), str(reason or ""), severity,
                _json(list(options)), timeout,
                iso_millis(requested),
                iso_millis(requested + timedelta(seconds=timeout)),
                iso_millis(current),
            ),
        )
        return self.lookup(approval_id) or {
            "approvalId": approval_id, "conversationId": conversation_id,
            "decision": None,
        }

    def lookup(self, approval_id: str) -> dict[str, Any] | None:
        row = self.store.database.execute(
            "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
        ).fetchone()
        return None if row is None else self._map(row)

    def settle(
        self,
        approval_id: str,
        decision: str,
        *,
        device_id: str | None = None,
        now: datetime | str | None = None,
    ) -> bool:
        """Write the first decision for one approval. False when already settled.

        A settled approval never changes its mind: a second decision that differs
        is reported as the conflict it is, and only an identical replay is
        accepted as the idempotent retry it is.
        """
        row = self.store.database.execute(
            "SELECT decision FROM approvals WHERE approval_id = ?", (approval_id,)
        ).fetchone()
        if row is None:
            return False
        if row["decision"] is not None:
            return False
        current = iso_millis(_now(now))
        cursor = self.store.database.execute(
            """
            UPDATE approvals SET decision = ?, decided_at = ?, decided_by_device_id = ?
            WHERE approval_id = ? AND decision IS NULL
            """,
            (decision, current, device_id, approval_id),
        )
        return cursor.rowcount > 0

    def pending_expired(self, now: datetime | str | None = None) -> list[dict[str, Any]]:
        """Approvals whose window closed without an answer (contract §7.2)."""
        rows = self.store.database.execute(
            "SELECT * FROM approvals WHERE decision IS NULL AND expires_at <= ? ORDER BY expires_at, approval_id",
            (iso_millis(_now(now)),),
        ).fetchall()
        return [self._map(row) for row in rows]

    def _map(self, row: sqlite3.Row) -> dict[str, Any]:
        options: Any = []
        try:
            options = json.loads(str(row["options_json"]))
        except Exception:
            options = []
        return {
            "approvalId": row["approval_id"],
            "conversationId": row["conversation_id"],
            "sessionKey": row["session_key"],
            "hostRequestId": row["host_request_id"],
            "command": row["command"],
            "reason": row["reason"],
            "severity": row["severity"],
            "options": options if isinstance(options, list) else [],
            "timeoutSeconds": row["timeout_seconds"],
            "requestedAt": _epoch_millis(row["requested_at"]),
            "expiresAt": _epoch_millis(row["expires_at"]),
            "decision": row["decision"],
            "decidedAt": _epoch_millis(row["decided_at"]) if row["decided_at"] else None,
            "decidedByDeviceId": row["decided_by_device_id"],
            "createdAt": row["created_at"],
        }


ATTACHMENT_STREAM_CHUNK_BYTES = 64 * 1024
_ATTACHMENT_STREAM_MAGIC = b"OAI-ATTACHMENT-AEAD-STREAM\x02\n"
_ATTACHMENT_STREAM_FRAME = struct.Struct(">II")
_MAX_SEALED_ATTACHMENT_CHUNK_BYTES = ATTACHMENT_STREAM_CHUNK_BYTES * 2 + 8192


@dataclass(frozen=True)
class StreamedAttachmentUpload:
    """Private encrypted spool handed from the HTTP stream reader to Core."""

    account_id: str
    attachment_id: str
    temporary_path: Path
    size_bytes: int
    sha256: str

    def discard(self) -> None:
        try:
            self.temporary_path.unlink(missing_ok=True)
        except OSError:
            pass


class _AttachmentUploadStream:
    """Bounded-memory writer for an authenticated attachment staging file."""

    def __init__(
        self, attachments: Any, attachment_id: str, row: sqlite3.Row,
        now: datetime | str | None,
    ):
        self.attachments = attachments
        self.attachment_id = attachment_id
        self.row = row
        self.now = now
        self.part_path = attachments.paths.attachments / f".{attachment_id}.{uuid.uuid4().hex}.upload"
        try:
            self.handle = self.part_path.open("xb")
            self.part_path.chmod(0o600)
            self.handle.write(_ATTACHMENT_STREAM_MAGIC)
        except OSError as exc:
            try:
                self.handle.close()
            except (AttributeError, OSError):
                pass
            self.part_path.unlink(missing_ok=True)
            raise GatewayError("ATTACHMENT_STORAGE_UNAVAILABLE") from exc
        except BaseException:
            try:
                self.handle.close()
            except OSError:
                pass
            self.part_path.unlink(missing_ok=True)
            raise
        self.byte_count = 0
        self.chunk_count = 0
        self.digest = hashlib.sha256()
        self.closed = False
        self.finished = False

    def _purpose(self, suffix: str) -> str:
        return (
            f"{self.attachments._attachment_aad(self.attachment_id, str(self.row['sha256']))}"
            f":stream-v2:{suffix}"
        )

    def _write_frame(self, plain_length: int, sealed: str) -> None:
        encoded = sealed.encode("ascii")
        if len(encoded) > _MAX_SEALED_ATTACHMENT_CHUNK_BYTES:
            raise GatewayError("ENCRYPTION_FAILED")
        self.handle.write(_ATTACHMENT_STREAM_FRAME.pack(plain_length, len(encoded)))
        self.handle.write(encoded)

    def write(self, chunk: bytes | bytearray | memoryview) -> None:
        if self.closed or self.finished:
            raise GatewayError("INVALID_STATE_TRANSITION")
        if not isinstance(chunk, (bytes, bytearray, memoryview)):
            raise GatewayError("REQUEST_BODY_INVALID")
        view = memoryview(chunk)
        for offset in range(0, len(view), ATTACHMENT_STREAM_CHUNK_BYTES):
            plain = bytes(view[offset:offset + ATTACHMENT_STREAM_CHUNK_BYTES])
            if self.byte_count + len(plain) > int(self.row["size_bytes"]):
                raise GatewayError("ATTACHMENT_DIGEST_MISMATCH")
            try:
                self.digest.update(plain)
                sealed = self.attachments.store.seal_bytes(
                    plain, self._purpose(f"chunk:{self.chunk_count}"),
                )
                self._write_frame(len(plain), sealed)
            except OSError as exc:
                raise GatewayError("ATTACHMENT_STORAGE_UNAVAILABLE") from exc
            self.byte_count += len(plain)
            self.chunk_count += 1

    def finish(self) -> StreamedAttachmentUpload:
        if self.closed or self.finished:
            raise GatewayError("INVALID_STATE_TRANSITION")
        actual_digest = self.digest.hexdigest()
        if (
            self.byte_count != int(self.row["size_bytes"])
            or actual_digest != str(self.row["sha256"])
        ):
            self.abort()
            raise GatewayError("ATTACHMENT_DIGEST_MISMATCH")

        final_purpose = self._purpose(
            f"final:{self.chunk_count}:{self.byte_count}:{actual_digest}"
        )
        try:
            self._write_frame(0, self.attachments.store.seal_bytes(b"", final_purpose))
            self.handle.flush()
            os.fsync(self.handle.fileno())
            self.handle.close()
            self.closed = True
        except OSError as exc:
            self.abort()
            raise GatewayError("ATTACHMENT_STORAGE_UNAVAILABLE") from exc
        self.finished = True
        return StreamedAttachmentUpload(
            self.attachments.account_id,
            self.attachment_id,
            self.part_path,
            self.byte_count,
            actual_digest,
        )

    def abort(self) -> None:
        if not self.closed:
            self.handle.close()
            self.closed = True
        try:
            self.part_path.unlink(missing_ok=True)
        except OSError:
            pass


class AttachmentStore:
    _UNATTRIBUTED_INTERNAL_OWNER = "__gateway_internal_unattributed__"

    def __init__(
        self, account_id: str, paths: AccountPaths, store: AccountStore,
        audit: AuditStore, policy: AttachmentPolicy | None = None,
        events: EventStore | None = None,
    ):
        self.account_id = account_id
        self.paths = paths
        self.store = store
        self.audit = audit
        self.policy = policy or DEFAULT_ATTACHMENT_POLICY
        self.events = events
        self.cas_dir = paths.attachments / "cas"
        self.cas_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            self.cas_dir.chmod(0o700)
        except OSError:
            pass
        self._reconcile_staged_files()
        self._recover_legacy_attachments()

    def create(self, **input: Any) -> dict[str, Any]:
        self.store.require_aead()
        current = _now(input.get("now"))
        raw_media_type = input["media_type"] if "media_type" in input else input["mediaType"]
        media_type = str(raw_media_type)
        size_bytes = int(input["size_bytes"] if "size_bytes" in input else input["sizeBytes"])
        client_attachment_id = (
            input["client_attachment_id"]
            if "client_attachment_id" in input
            else input["clientAttachmentId"]
        )
        filename = str(input["filename"])
        sha256 = str(input["sha256"])
        owner_device_id = str(input.get("device_id", input.get("deviceId", self._UNATTRIBUTED_INTERNAL_OWNER)))
        owner_pairing_generation = int(input.get("pairing_generation", input.get("pairingGeneration", 0)))
        if size_bytes < 0 or size_bytes > 0x7FFF_FFFF_FFFF_FFFF or not media_type:
            raise GatewayError("SCHEMA_INVALID")
        if not owner_device_id or owner_pairing_generation < 0:
            raise GatewayError("SCHEMA_INVALID")
        requested_expiry = input.get("expires_at") or input.get("expiresAt")
        if requested_expiry is None:
            expires_at = iso_millis(current + timedelta(seconds=self.policy.attachment_ttl_seconds))
        else:
            try:
                expiry = _now(requested_expiry)
            except (TypeError, ValueError, OverflowError) as exc:
                raise GatewayError("SCHEMA_INVALID") from exc
            maximum_expiry = current + timedelta(seconds=self.policy.attachment_ttl_seconds)
            if expiry <= current or expiry > maximum_expiry:
                raise GatewayError("SCHEMA_INVALID")
            expires_at = iso_millis(expiry)
        correlation_id = (
            input["correlation_id"] if "correlation_id" in input else input["correlationId"]
        )
        with self.store.transaction():
            existing_rows = self.store.database.execute(
                "SELECT attachment_id, filename, media_type, size_bytes, sha256, owner_device_id, owner_pairing_generation FROM attachments "
                "WHERE client_attachment_id = ? AND owner_device_id = ? AND owner_pairing_generation = ? ORDER BY created_at DESC",
                (client_attachment_id, owner_device_id, owner_pairing_generation),
            ).fetchall()
            if existing_rows:
                for existing in existing_rows:
                    if (
                        str(existing["filename"]) != filename
                        or str(existing["media_type"]) != media_type
                        or int(existing["size_bytes"]) != size_bytes
                        or str(existing["sha256"]) != sha256
                    ):
                        raise GatewayError("IDEMPOTENCY_CONFLICT")
                attachment_id = str(existing_rows[0]["attachment_id"])
            else:
                attachment_id = f"att_{uuid.uuid4()}"
                self.store.database.execute(
                    """
                    INSERT INTO attachments(attachment_id, client_attachment_id, filename, media_type, size_bytes,
                      sha256, state, content_path, cas_path, created_at, expires_at, delivered_at, acknowledged_at,
                      owner_device_id, owner_pairing_generation)
                    VALUES (?, ?, ?, ?, ?, ?, 'created', NULL, NULL, ?, ?, NULL, NULL, ?, ?)
                    """,
                    (
                        attachment_id, client_attachment_id, filename, media_type,
                        size_bytes, sha256, iso_millis(current), expires_at,
                        owner_device_id, owner_pairing_generation,
                    ),
                )
                self.audit.append(
                    "attachment.created", {"accountId": self.account_id},
                    {"attachmentId": attachment_id, "mediaType": media_type, "sizeBytes": size_bytes},
                    correlation_id, current,
                )
        return self.get(attachment_id, current)

    def get_record(self, attachment_id: str, now: datetime | str | None = None) -> dict[str, Any]:
        """Read internal metadata, including storage state, without wire projection."""
        row, _ = self._expire_if_due(attachment_id, _now(now))
        path = row["content_path"]
        return {
            "attachmentId": row["attachment_id"], "state": row["state"],
            "status": _ATTACHMENT_PUBLIC_STATUS.get(str(row["state"]), "failed"),
            "filename": row["filename"], "mediaType": row["media_type"],
            "sizeBytes": int(row["size_bytes"]), "sha256": row["sha256"],
            "hasStagedBytes": bool(path and Path(path).is_file()), "expiresAt": row["expires_at"],
        }

    def get(self, attachment_id: str, now: datetime | str | None = None) -> dict[str, Any]:
        """Return exactly the shared attachment status resource DTO."""
        record = self.get_record(attachment_id, now)
        return {
            "attachmentId": record["attachmentId"],
            "status": record["status"],
            "sizeBytes": record["sizeBytes"],
            "sha256": record["sha256"],
        }

    def require_verified_for_message(self, attachment_id: str, now: datetime | str | None = None) -> None:
        row, expired = self._expire_if_due(attachment_id, _now(now))
        if expired or row["state"] != "verified":
            raise GatewayError("ATTACHMENT_EXPIRED")

    def upload_content(
        self, attachment_id: str, content: bytes, now: datetime | str | None = None,
    ) -> dict[str, Any]:
        return self.upload_content_stream(attachment_id, (content,), now=now)

    def begin_content_upload_stream(
        self,
        attachment_id: str,
        content_length: int,
        content_sha256: str,
        now: datetime | str | None = None,
        content_type: str | None = None,
    ) -> _AttachmentUploadStream:
        """Start an account-scoped encrypted upload after its signed metadata matches."""
        row, expired = self._expire_if_due(attachment_id, _now(now))
        if expired or row["state"] == "expired":
            raise GatewayError("ATTACHMENT_EXPIRED")
        if (
            not isinstance(content_length, int)
            or content_length != int(row["size_bytes"])
            or content_sha256 != str(row["sha256"])
            or (content_type is not None and content_type != str(row["media_type"]))
        ):
            raise GatewayError("ATTACHMENT_DIGEST_MISMATCH")
        return _AttachmentUploadStream(self, attachment_id, row, now)

    def upload_content_stream(
        self,
        attachment_id: str,
        chunks: Iterable[bytes | bytearray | memoryview],
        *,
        now: datetime | str | None = None,
    ) -> dict[str, Any]:
        """Encrypt an iterable of body chunks without joining them in memory."""
        record = self.get(attachment_id, now)
        upload = self.begin_content_upload_stream(
            attachment_id, int(record["sizeBytes"]), str(record["sha256"]), now,
        )
        try:
            for chunk in chunks:
                upload.write(chunk)
            staged = upload.finish()
            try:
                return self.accept_streamed_upload(staged, now)
            finally:
                staged.discard()
        except BaseException:
            upload.abort()
            raise

    def accept_streamed_upload(
        self, staged: StreamedAttachmentUpload, now: datetime | str | None = None,
    ) -> dict[str, Any]:
        """Promote a finished encrypted spool to this account's attachment stage."""
        if (
            staged.account_id != self.account_id
            or staged.temporary_path.parent.resolve() != self.paths.attachments.resolve()
            or not staged.temporary_path.name.startswith(f".{staged.attachment_id}.")
            or not staged.temporary_path.name.endswith(".upload")
        ):
            raise GatewayError("SCHEMA_INVALID")
        current = _now(now)
        row, expired = self._expire_if_due(staged.attachment_id, current)
        if expired or row["state"] == "expired":
            raise GatewayError("ATTACHMENT_EXPIRED")
        if (
            int(row["size_bytes"]) != staged.size_bytes
            or str(row["sha256"]) != staged.sha256
        ):
            raise GatewayError("ATTACHMENT_DIGEST_MISMATCH")
        if row["state"] in {"uploading", "verified", "delivered"}:
            existing_path_value = row["cas_path"] or row["content_path"]
            if not existing_path_value:
                raise GatewayError("ATTACHMENT_READ_FAILED")
            try:
                for _chunk in self._iter_decrypted_content(row, Path(existing_path_value)):
                    pass
            except GatewayError as exc:
                raise GatewayError("ATTACHMENT_READ_FAILED") from exc
            return self.get(staged.attachment_id, now)
        if row["state"] == "acknowledged":
            # The original bytes have already been handed to Hermes and ACKed;
            # the signed retry is content-identical by the metadata checks above.
            return self.get(staged.attachment_id, now)
        if row["state"] != "created":
            raise GatewayError("ATTACHMENT_DIGEST_MISMATCH")
        stage_path = self.paths.attachments / f"{staged.attachment_id}.stage"
        try:
            with self.store.transaction():
                row = self._row(staged.attachment_id)
                next_state = next_attachment_state(row["state"], "begin_upload")
                os.replace(staged.temporary_path, stage_path)
                try:
                    stage_path.chmod(0o600)
                except OSError:
                    pass
                self.store.database.execute(
                    "UPDATE attachments SET state = ?, content_path = ?, storage_revision = storage_revision + 1 WHERE attachment_id = ?",
                    (next_state, str(stage_path), staged.attachment_id),
                )
        except OSError as exc:
            self._reconcile_staged_files()
            staged.discard()
            raise GatewayError("ATTACHMENT_STORAGE_UNAVAILABLE") from exc
        except BaseException:
            self._reconcile_staged_files()
            raise
        return self.get(staged.attachment_id, now)

    @property
    def stream_chunk_bytes(self) -> int:
        return ATTACHMENT_STREAM_CHUNK_BYTES

    def _iter_decrypted_content(self, row: sqlite3.Row, path: Path) -> Iterator[bytes]:
        """Yield authenticated plaintext records and verify the whole object at EOF."""
        try:
            with path.open("rb") as handle:
                prefix = handle.read(len(_ATTACHMENT_STREAM_MAGIC))
                if prefix != _ATTACHMENT_STREAM_MAGIC:
                    # The host AEAD API authenticates one-shot byte strings. A
                    # v1 attachment therefore cannot be safely decrypted with
                    # bounded memory. Startup recovery marks it failed and asks
                    # the sender to upload it again in the chunked v2 format.
                    raise GatewayError("DECRYPTION_FAILED")

                index = 0
                total = 0
                digest = hashlib.sha256()
                while True:
                    frame = handle.read(_ATTACHMENT_STREAM_FRAME.size)
                    if len(frame) != _ATTACHMENT_STREAM_FRAME.size:
                        raise GatewayError("DECRYPTION_FAILED")
                    plain_length, sealed_length = _ATTACHMENT_STREAM_FRAME.unpack(frame)
                    if sealed_length <= 0 or sealed_length > _MAX_SEALED_ATTACHMENT_CHUNK_BYTES:
                        raise GatewayError("DECRYPTION_FAILED")
                    sealed_bytes = handle.read(sealed_length)
                    if len(sealed_bytes) != sealed_length:
                        raise GatewayError("DECRYPTION_FAILED")
                    try:
                        sealed = sealed_bytes.decode("ascii")
                    except UnicodeDecodeError as exc:
                        raise GatewayError("DECRYPTION_FAILED") from exc
                    if plain_length == 0:
                        final_purpose = (
                            f"{self._attachment_aad(str(row['attachment_id']), str(row['sha256']))}:stream-v2:"
                            f"final:{index}:{total}:{digest.hexdigest()}"
                        )
                        if self.store.open_bytes(sealed, final_purpose) != b"" or handle.read(1):
                            raise GatewayError("DECRYPTION_FAILED")
                        if (
                            total != int(row["size_bytes"])
                            or digest.hexdigest() != str(row["sha256"])
                        ):
                            raise GatewayError("ATTACHMENT_DIGEST_MISMATCH")
                        return
                    if plain_length > ATTACHMENT_STREAM_CHUNK_BYTES:
                        raise GatewayError("DECRYPTION_FAILED")
                    purpose = (
                        f"{self._attachment_aad(str(row['attachment_id']), str(row['sha256']))}:stream-v2:chunk:{index}"
                    )
                    plaintext = self.store.open_bytes(sealed, purpose)
                    if len(plaintext) != plain_length:
                        raise GatewayError("DECRYPTION_FAILED")
                    total += len(plaintext)
                    if total > int(row["size_bytes"]):
                        raise GatewayError("ATTACHMENT_DIGEST_MISMATCH")
                    digest.update(plaintext)
                    index += 1
                    yield plaintext
        except GatewayError:
            raise
        except OSError as exc:
            raise GatewayError("ATTACHMENT_STORAGE_UNAVAILABLE") from exc
        except (UnicodeDecodeError, ValueError, struct.error) as exc:
            raise GatewayError("DECRYPTION_FAILED") from exc

    def open_verified_stream(
        self, attachment_id: str, now: datetime | str | None = None,
    ) -> Iterator[bytes]:
        """Open a verified attachment belonging to this account as bounded chunks."""
        row, expired = self._expire_if_due(attachment_id, _now(now))
        if expired or row["state"] not in {"verified", "delivered"}:
            raise GatewayError("ATTACHMENT_EXPIRED")
        raw_path = row["cas_path"] or row["content_path"]
        if not raw_path:
            raise GatewayError("ATTACHMENT_EXPIRED")
        path = Path(raw_path)
        if not path.is_file():
            raise GatewayError("ATTACHMENT_EXPIRED")
        return self._iter_decrypted_content(row, path)

    def commit(self, attachment_id: str, now: datetime | str | None = None) -> dict[str, Any]:
        mismatch = False
        row, expired = self._expire_if_due(attachment_id, _now(now))
        if expired or row["state"] == "expired":
            raise GatewayError("ATTACHMENT_EXPIRED")
        with self.store.transaction():
            row = self._row(attachment_id)
            stage_path = self._require_content_path(row)
            try:
                for _chunk in self._iter_decrypted_content(row, stage_path):
                    pass
            except GatewayError as exc:
                if exc.code != "ATTACHMENT_DIGEST_MISMATCH":
                    raise
                self.store.database.execute(
                    "UPDATE attachments SET state = ?, content_path = ?, storage_revision = storage_revision + 1 WHERE attachment_id = ?",
                    (next_attachment_state(row["state"], "fail"), str(stage_path), attachment_id),
                )
                mismatch = True
            else:
                cas_path = self.cas_dir / attachment_id
                if not cas_path.exists():
                    shutil.copyfile(stage_path, cas_path)
                    try:
                        cas_path.chmod(0o600)
                    except OSError:
                        pass
                self.store.database.execute(
                    "UPDATE attachments SET state = ?, cas_path = ?, storage_revision = storage_revision + 1 WHERE attachment_id = ?",
                    (next_attachment_state(row["state"], "verify"), str(cas_path), attachment_id),
                )
        if mismatch:
            raise GatewayError("ATTACHMENT_DIGEST_MISMATCH")
        return self.get(attachment_id, now)

    def mark_delivered(self, attachment_id: str, now: datetime | str | None = None) -> dict[str, Any]:
        current = _now(now)
        row, expired = self._expire_if_due(attachment_id, current)
        if expired or row["state"] == "expired":
            raise GatewayError("ATTACHMENT_EXPIRED")
        with self.store.transaction():
            row = self._row(attachment_id)
            state = next_attachment_state(row["state"], "deliver")
            self.store.database.execute(
                "UPDATE attachments SET state = ?, delivered_at = ?, storage_revision = storage_revision + 1 WHERE attachment_id = ?",
                (state, iso_millis(current), attachment_id),
            )
        return self.get(attachment_id, now)

    def acknowledge(self, attachment_id: str, correlation_id: str, now: datetime | str | None = None) -> dict[str, Any]:
        current = _now(now)
        row, expired = self._expire_if_due(attachment_id, current)
        if expired or row["state"] == "expired":
            raise GatewayError("ATTACHMENT_EXPIRED")
        paths: list[Path] = []
        with self.store.transaction():
            row = self._row(attachment_id)
            for key in ("content_path", "cas_path"):
                if row[key]:
                    paths.append(Path(row[key]))
            state = next_attachment_state(row["state"], "acknowledge")
            self.store.database.execute(
                "UPDATE attachments SET state = ?, content_path = NULL, cas_path = NULL, acknowledged_at = ?, storage_revision = storage_revision + 1 WHERE attachment_id = ?",
                (state, iso_millis(current), attachment_id),
            )
            self.audit.append(
                "attachment.acknowledged", {"accountId": self.account_id},
                {"attachmentId": attachment_id}, correlation_id, current,
            )
            if self.events is None:
                raise GatewayError("INTERNAL_ERROR")
            self.events.append(
                "attachment.acknowledged", correlation_id,
                {"attachmentId": attachment_id}, current,
            )
        cas_path = next((path for path in paths if path.parent == self.cas_dir), None)
        if cas_path is not None:
            remaining = self.store.database.execute(
                "SELECT 1 FROM attachments WHERE cas_path = ? LIMIT 1", (str(cas_path),)
            ).fetchone()
            if remaining is not None:
                paths = [path for path in paths if path != cas_path]
        for path in paths:
            self._move_to_trash(path)
        return self.get(attachment_id, now)

    def expire_due(self, now: datetime | str | None = None) -> int:
        current = _now(now)
        self._reconcile_staged_files()
        rows = self.store.database.execute(
            "SELECT attachment_id FROM attachments WHERE expires_at <= ? AND state IN ('created', 'uploading', 'verified', 'delivered')",
            (iso_millis(current),),
        ).fetchall()
        expired = 0
        for row_ref in rows:
            paths: list[Path] = []
            with self.store.transaction():
                row = self._row(row_ref["attachment_id"])
                if _now(row["expires_at"]) > current or row["state"] not in {"created", "uploading", "verified", "delivered"}:
                    continue
                for key in ("content_path", "cas_path"):
                    if row[key]:
                        paths.append(Path(row[key]))
                state = next_attachment_state(row["state"], "expire")
                self.store.database.execute(
                    "UPDATE attachments SET state = ?, content_path = NULL, cas_path = NULL, storage_revision = storage_revision + 1 WHERE attachment_id = ?",
                    (state, row["attachment_id"]),
                )
                expired += 1
            for path in paths:
                self._move_unreferenced_path(path)
        return expired

    def cleanup(self, now: datetime | str | None = None) -> int:
        self.expire_due(now)
        protected = self._reconcile_staged_files()
        paths: list[Path] = []
        with self.store.transaction():
            rows = self.store.database.execute(
                "SELECT attachment_id, content_path, cas_path, state FROM attachments WHERE state IN ('acknowledged', 'failed', 'expired')"
            ).fetchall()
            for row in rows:
                for key in ("content_path", "cas_path"):
                    if row[key]:
                        paths.append(Path(row[key]))
                self.store.database.execute(
                    "UPDATE attachments SET state = ?, content_path = NULL, cas_path = NULL, storage_revision = storage_revision + 1 WHERE attachment_id = ?",
                    (next_attachment_state(row["state"], "cleanup"), row["attachment_id"]),
                )
            referenced = {
                Path(item[0]) for item in self.store.database.execute(
                    "SELECT content_path FROM attachments WHERE content_path IS NOT NULL"
                ).fetchall()
            }
            referenced.update(
                Path(item[0]) for item in self.store.database.execute(
                    "SELECT cas_path FROM attachments WHERE cas_path IS NOT NULL"
                ).fetchall()
            )
            for staged in self.paths.attachments.glob("*.stage"):
                if staged not in referenced and staged not in protected:
                    paths.append(staged)
            for cas in self.cas_dir.glob("*"):
                if cas.is_file() and cas not in referenced:
                    paths.append(cas)
        deleted = 0
        for path in set(paths):
            if self._move_to_trash(path):
                deleted += 1
        return deleted

    def revoke_unconfirmed(
        self, device_id: str, pairing_generation: int, correlation_id: str,
        now: datetime | str | None = None,
    ) -> int:
        """Destroys unconfirmed attachments created by one pairing only.

        Contract section 13 (`:798`) revokes "unconfirmed attachments" when a
        pairing ends. Unconfirmed means the host never acknowledged it: the
        bytes are still staged for delivery and nothing else keeps them alive.

        The row itself is kept as the audit trail of what existed and is moved
        straight to `deleted` — revocation is a deletion, not one of the
        lifecycle transitions of `_ATTACHMENT_TRANSITIONS`.

        Legacy rows without pairing attribution are left to their original TTL
        cleanup. Guessing an owner would risk deleting another device's bytes.
        """
        current = _now(now)
        paths: list[Path] = []
        with self.store.transaction():
            rows = self.store.database.execute(
                "SELECT attachment_id, content_path, cas_path FROM attachments "
                "WHERE acknowledged_at IS NULL AND state != 'deleted' "
                "AND owner_device_id = ? AND owner_pairing_generation = ?",
                (device_id, pairing_generation),
            ).fetchall()
            for row in rows:
                for key in ("content_path", "cas_path"):
                    if row[key]:
                        paths.append(Path(row[key]))
                self.store.database.execute(
                    "UPDATE attachments SET state = 'deleted', content_path = NULL, cas_path = NULL, storage_revision = storage_revision + 1 WHERE attachment_id = ?",
                    (row["attachment_id"],),
                )
                self.audit.append(
                    "attachment.revoked", {"accountId": self.account_id, "deviceId": device_id},
                    {
                        "attachmentId": row["attachment_id"],
                        "pairingGeneration": pairing_generation,
                    }, correlation_id, current,
                )
        for path in set(paths):
            self._move_to_trash(path)
        return len(rows)

    revokeUnconfirmed = revoke_unconfirmed

    def _expire_if_due(self, attachment_id: str, current: datetime) -> tuple[sqlite3.Row, bool]:
        paths: list[Path] = []
        expired = False
        with self.store.transaction():
            row = self._row(attachment_id)
            if (
                _now(row["expires_at"]) <= current
                and row["state"] in {"created", "uploading", "verified", "delivered"}
            ):
                for key in ("content_path", "cas_path"):
                    if row[key]:
                        paths.append(Path(row[key]))
                self.store.database.execute(
                    "UPDATE attachments SET state = 'expired', content_path = NULL, cas_path = NULL, storage_revision = storage_revision + 1 WHERE attachment_id = ?",
                    (attachment_id,),
                )
                row = self._row(attachment_id)
                expired = True
        for path in paths:
            self._move_unreferenced_path(path)
        return row, expired

    def _row(self, attachment_id: str) -> sqlite3.Row:
        row = self.store.database.execute("SELECT * FROM attachments WHERE attachment_id = ?", (attachment_id,)).fetchone()
        if row is None:
            raise GatewayError("ATTACHMENT_EXPIRED")
        return row

    def _legacy_attachment_aad(self, sha256: str) -> str:
        return f"open-android-intelligence:attachment:v1:{self.account_id}:{sha256}"

    def _attachment_aad(self, attachment_id: str, sha256: str) -> str:
        return f"open-android-intelligence:attachment:v2:{self.account_id}:{attachment_id}:{sha256}"

    def _recover_legacy_attachments(self) -> int:
        """Drain old one-shot stages transactionally so clients can re-upload.

        The old AEAD format authenticated the entire body as one value and has
        no bounded-memory streaming decrypt operation. Re-encrypting it would
        restore the full body in memory, so startup drains those legacy stages
        and returns an explicit re-upload state. Each metadata transition and
        audit record commit before bytes are removed; a failed transaction
        leaves the original row and bytes intact for the next startup retry.
        """
        rows = self.store.database.execute(
            "SELECT attachment_id, state, content_path, cas_path, sha256 FROM attachments "
            "WHERE state IN ('uploading', 'verified', 'delivered')"
        ).fetchall()
        recovered = 0
        for row in rows:
            paths = [Path(row[key]) for key in ("content_path", "cas_path") if row[key]]
            if not paths:
                continue
            legacy = False
            for path in paths:
                try:
                    with path.open("rb") as handle:
                        prefix = handle.read(max(len(_ATTACHMENT_STREAM_MAGIC), len(b"aead-v1:")))
                        if prefix.startswith(b"aead-v1:"):
                            legacy = True
                            break
                except FileNotFoundError:
                    # Existing reconciliation owns missing/corrupt paths.
                    continue
                except OSError as exc:
                    raise GatewayError("ATTACHMENT_STORAGE_UNAVAILABLE") from exc
            if not legacy:
                continue
            with self.store.transaction():
                current = self._row(str(row["attachment_id"]))
                if current["state"] not in {"uploading", "verified", "delivered"}:
                    continue
                self.store.database.execute(
                    "UPDATE attachments SET state = ?, content_path = NULL, cas_path = NULL, storage_revision = storage_revision + 1 WHERE attachment_id = ?",
                    (next_attachment_state(str(current["state"]), "fail"), row["attachment_id"]),
                )
                self.audit.append(
                    "attachment.legacy_format.requires_reupload",
                    {"accountId": self.account_id},
                    {"attachmentId": row["attachment_id"], "format": "aead-v1"},
                    f"legacy-recovery:{row['attachment_id']}",
                )
            for path in paths:
                self._move_unreferenced_path(path)
            recovered += 1
        return recovered

    def recover_interrupted_uploads(self) -> int:
        """Remove encrypted temp and orphan files before HTTP serving starts."""
        referenced = {
            Path(row[0]) for row in self.store.database.execute(
                "SELECT content_path FROM attachments WHERE content_path IS NOT NULL"
            ).fetchall()
        }
        referenced.update(
            Path(row[0]) for row in self.store.database.execute(
                "SELECT cas_path FROM attachments WHERE cas_path IS NOT NULL"
            ).fetchall()
        )
        candidates = list(self.paths.attachments.glob(".*.upload"))
        candidates.extend(
            path for path in self.paths.attachments.glob("*.stage")
            if path not in referenced
        )
        candidates.extend(
            path for path in self.cas_dir.glob("*")
            if path.is_file() and path not in referenced
        )
        removed = 0
        for path in set(candidates):
            if self._move_unreferenced_path(path):
                removed += 1
        return removed

    def _require_content_path(self, row: sqlite3.Row) -> Path:
        path = Path(row["content_path"]) if row["content_path"] else None
        if path is None or not path.is_file():
            raise GatewayError("ATTACHMENT_EXPIRED")
        return path

    @staticmethod
    def _trash_root() -> Path:
        root = Path("/tmp/Open Android Intelligence-trash")
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        return root

    @classmethod
    def _move_to_trash(cls, path: Path) -> bool:
        # These bytes are application-managed transport secrets, not user files.
        # Renaming them into /tmp retained recoverable ciphertext after ACK/TTL.
        try:
            existed = path.exists()
            path.unlink(missing_ok=True)
            # Also remove older copies of this exact attachment, never unrelated
            # files from the shared legacy trash directory.
            for old_copy in cls._trash_root().glob(f"*-{path.name}"):
                if old_copy.is_file() and not old_copy.is_symlink():
                    old_copy.unlink()
                    existed = True
            return existed
        except OSError:
            return False

    def _move_unreferenced_path(self, path: Path) -> bool:
        if path.parent == self.cas_dir:
            referenced = self.store.database.execute(
                "SELECT 1 FROM attachments WHERE cas_path = ? LIMIT 1", (str(path),)
            ).fetchone()
            if referenced is not None:
                return False
        return self._move_to_trash(path)

    def _reconcile_staged_files(self) -> set[Path]:
        protected: set[Path] = set()
        for path in self.paths.attachments.glob("*.stage"):
            attachment_id = path.name[:-len(".stage")]
            row = self.store.database.execute("SELECT state, content_path FROM attachments WHERE attachment_id = ?", (attachment_id,)).fetchone()
            if row is None or row["state"] not in {"created", "uploading", "verified", "delivered", "failed"}:
                continue
            if row["content_path"] != str(path) or row["state"] == "created":
                try:
                    self.store.database.execute(
                        "UPDATE attachments SET state = ?, content_path = ?, storage_revision = storage_revision + 1 WHERE attachment_id = ?",
                        ("uploading" if row["state"] == "created" else row["state"], str(path), attachment_id),
                    )
                except sqlite3.Error:
                    protected.add(path)
        return protected

    uploadContent = upload_content
    markDelivered = mark_delivered
    expireDue = expire_due
    requireVerifiedForMessage = require_verified_for_message


class DeviceRequestStore:
    def __init__(self, account_id: str, store: AccountStore, audit: AuditStore, events: EventStore, contracts: ContractRegistry | None = None):
        self.account_id = account_id
        self.store = store
        self.audit = audit
        self.events = events
        self.contracts = contracts or ContractRegistry()
        from .capability_bindings import CapabilityBindings
        self.capabilities = CapabilityBindings(store, self.contracts)

    def enqueue(
        self, request_id: str | None = None, device_id: str | None = None,
        pairing_generation: int | None = None, grant_revision: int | None = None,
        risk: str | None = None, capability: Mapping[str, Any] | None = None,
        provider: Mapping[str, Any] | None = None, parameters: Mapping[str, Any] | None = None,
        correlation_id: str | None = None, now: datetime | str | None = None,
        requires_foreground_confirmation: bool | None = None, online: bool = False, **aliases: Any,
    ) -> dict[str, Any]:
        request_id = request_id if request_id is not None else aliases.pop("requestId")
        device_id = device_id if device_id is not None else aliases.pop("deviceId")
        pairing_generation = pairing_generation if pairing_generation is not None else aliases.pop("pairingGeneration")
        grant_revision = grant_revision if grant_revision is not None else aliases.pop("grantRevision")
        risk = risk if risk is not None else aliases.pop("risk")
        capability = capability if capability is not None else aliases.pop("capability")
        provider = provider if provider is not None else aliases.pop("provider")
        parameters = parameters if parameters is not None else aliases.pop("parameters")
        correlation_id = correlation_id if correlation_id is not None else aliases.pop("correlationId")
        requires_foreground_confirmation = (
            requires_foreground_confirmation
            if requires_foreground_confirmation is not None
            else aliases.pop("requiresForegroundConfirmation", False)
        )
        current = _now(now)
        ttl = maximum_device_request_queue_seconds(risk)
        state = "expired" if ttl == 0 and not online else "pending"
        expires_at = iso_millis(current + timedelta(seconds=ttl or (30 if online else 0)))
        record = {
            "requestId": request_id,
            "capability": dict(capability),
            "provider": dict(provider),
            "parameters": dict(parameters),
            "risk": risk,
            "grantRevision": int(grant_revision),
            "createdAt": iso_millis(current),
            "expiresAt": expires_at,
            "requiresForegroundConfirmation": risk == "high-privilege-ephemeral" or bool(requires_foreground_confirmation),
        }
        if not self.capabilities.validate(device_id, int(pairing_generation), int(grant_revision), record):
            raise GatewayError("SCHEMA_INVALID")
        parameters_json = "" if state == "expired" else self.store.seal_json(
            parameters, f"device-request:{self.account_id}:{request_id}:parameters"
        )
        with self.store.transaction():
            self.store.database.execute(
                """
                INSERT INTO device_requests(request_id, device_id, pairing_generation, grant_revision, risk, state,
                  capability_json, provider_json, parameters_json, created_at, expires_at, requires_foreground_confirmation)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (request_id, device_id, pairing_generation, grant_revision, risk, state,
                 _json(capability), _json(provider), parameters_json, record["createdAt"], expires_at,
                 int(record["requiresForegroundConfirmation"])),
            )
            if state == "pending":
                self.events.append("device.requested", correlation_id, record, current)
            self.audit.append(
                "device.request.enqueued", {"accountId": self.account_id, "deviceId": device_id},
                {"requestId": request_id, "risk": risk, "grantRevision": grant_revision, "state": state},
                correlation_id, current,
            )
        return self.get(request_id)

    def claim(
        self, request_id: str, device_id: str, pairing_generation: int,
        grant_revision: int, correlation_id: str, now: datetime | str | None = None,
    ) -> dict[str, Any]:
        current = _now(now)
        expired = False
        with self.store.transaction():
            row = self._row(request_id)
            self._assert_binding(row, device_id, pairing_generation, grant_revision)
            if self._expire_if_due(row, current):
                expired = True
            else:
                receipt = self.store.database.execute("SELECT * FROM claim_receipts WHERE request_id = ?", (request_id,)).fetchone()
                if receipt is not None:
                    return self._receipt(receipt)
                if row["state"] != "pending":
                    raise GatewayError("OUTCOME_UNKNOWN")
                changed = self.store.database.execute(
                    "UPDATE device_requests SET state = 'claimed' WHERE request_id = ? AND state = 'pending' AND device_id = ? AND pairing_generation = ? AND grant_revision = ?",
                    (request_id, device_id, pairing_generation, grant_revision),
                ).rowcount
                if changed != 1:
                    raise GatewayError("OUTCOME_UNKNOWN")
                claim_id = f"claim_{uuid.uuid4()}"
                self.store.database.execute(
                    "INSERT INTO claim_receipts(claim_id, request_id, device_id, pairing_generation, grant_revision, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (claim_id, request_id, device_id, pairing_generation, grant_revision, iso_millis(current)),
                )
                self.audit.append(
                    "device.request.claimed", {"accountId": self.account_id, "deviceId": device_id},
                    {"requestId": request_id, "claimId": claim_id, "grantRevision": grant_revision},
                    correlation_id, current,
                )
                return {
                    "claimId": claim_id, "requestId": request_id, "accountId": self.account_id,
                    "deviceId": device_id, "pairingGeneration": pairing_generation,
                    "grantRevision": grant_revision,
                }
        if expired:
            raise GatewayError("OUTCOME_UNKNOWN")
        raise GatewayError("OUTCOME_UNKNOWN")

    def submit_result(
        self, request_id: str, device_id: str, pairing_generation: int,
        grant_revision: int, claim_id: str, result: Mapping[str, Any],
        correlation_id: str, now: datetime | str | None = None,
    ) -> dict[str, Any]:
        current = _now(now)
        expired = False
        record: dict[str, Any] | None = None
        with self.store.transaction():
            row = self._row(request_id)
            self._assert_binding(row, device_id, pairing_generation, grant_revision)
            if self._expire_if_due(row, current):
                expired = True
            else:
                receipt = self.store.database.execute(
                    "SELECT * FROM claim_receipts WHERE request_id = ? AND claim_id = ?", (request_id, claim_id)
                ).fetchone()
                if receipt is None:
                    raise GatewayError("OUTCOME_UNKNOWN")
                self._assert_binding(receipt, device_id, pairing_generation, grant_revision)
                if row["state"] not in {"claimed", "cancel_requested"}:
                    raise GatewayError("OUTCOME_UNKNOWN")
                outcome = result.get("outcome")
                event = "result_outcome_unknown" if outcome == "outcome_unknown" else f"result_{outcome}"
                next_state = next_device_request_state(row["state"], event)
                sealed_result = self.store.seal_json(result, f"device-result:{request_id}:{claim_id}")
                self.store.database.execute("UPDATE device_requests SET state = ?, parameters_json = '', result_json = ? WHERE request_id = ?", (next_state, sealed_result, request_id))
                self.events.release_device_request(request_id)
                self.audit.append(
                    "device.request.result", {"accountId": self.account_id, "deviceId": device_id},
                    {"requestId": request_id, "claimId": claim_id, "outcome": outcome},
                    correlation_id, current,
                )
                record = self.get(request_id)
        if expired:
            raise GatewayError("OUTCOME_UNKNOWN")
        if record is None:
            raise GatewayError("OUTCOME_UNKNOWN")
        return record

    def validate_claim_replay(
        self, request_id: str, device_id: str, pairing_generation: int,
        grant_revision: int, now: datetime | str | None = None,
    ) -> str | None:
        current = _now(now)
        with self.store.transaction():
            row = self._row(request_id)
            self._assert_binding(row, device_id, pairing_generation, grant_revision)
            if self._expire_if_due(row, current):
                return "OUTCOME_UNKNOWN"
            receipt = self.store.database.execute("SELECT * FROM claim_receipts WHERE request_id = ?", (request_id,)).fetchone()
            if receipt is None:
                raise GatewayError("OUTCOME_UNKNOWN")
            self._assert_binding(receipt, device_id, pairing_generation, grant_revision)
            return None

    def read_result(self, request_id: str, claim_id: str, now: datetime | str | None = None) -> dict[str, Any] | None:
        row = self._row(request_id)
        receipt = self.store.database.execute("SELECT 1 FROM claim_receipts WHERE request_id = ? AND claim_id = ?", (request_id, claim_id)).fetchone()
        if receipt is None:
            raise GatewayError("OUTCOME_UNKNOWN")
        if _now(row["expires_at"]) <= _now(now):
            self.store.database.execute("UPDATE device_requests SET result_json = '', parameters_json = '' WHERE request_id = ?", (request_id,))
            return None
        return self.store.open_json(row["result_json"], f"device-result:{request_id}:{claim_id}") if row["result_json"] else None

    def acknowledge_result(self, request_id: str, claim_id: str) -> None:
        receipt = self.store.database.execute("SELECT 1 FROM claim_receipts WHERE request_id = ? AND claim_id = ?", (request_id, claim_id)).fetchone()
        if receipt is None:
            raise GatewayError("OUTCOME_UNKNOWN")
        self.store.database.execute("UPDATE device_requests SET result_json = '' WHERE request_id = ?", (request_id,))
        self.events.release_device_request(request_id)

    def purge_terminal_payloads(self, now: datetime | str | None = None) -> int:
        return self.store.database.execute(
            "UPDATE device_requests SET result_json = '', parameters_json = '' WHERE request_id IN (SELECT request_id FROM device_requests WHERE expires_at <= ? AND (result_json != '' OR parameters_json != '') LIMIT 1000)",
            (iso_millis(now),),
        ).rowcount

    def validate_result_replay(
        self, request_id: str, device_id: str, pairing_generation: int,
        grant_revision: int, claim_id: str, now: datetime | str | None = None,
    ) -> str | None:
        current = _now(now)
        with self.store.transaction():
            row = self._row(request_id)
            self._assert_binding(row, device_id, pairing_generation, grant_revision)
            if self._expire_if_due(row, current):
                return "OUTCOME_UNKNOWN"
            receipt = self.store.database.execute(
                "SELECT * FROM claim_receipts WHERE request_id = ? AND claim_id = ?", (request_id, claim_id)
            ).fetchone()
            if receipt is None:
                raise GatewayError("OUTCOME_UNKNOWN")
            self._assert_binding(receipt, device_id, pairing_generation, grant_revision)
            return None

    def recover_expired(self, now: datetime | str | None = None) -> int:
        current = _now(now)
        rows = self.store.database.execute(
            "SELECT request_id, state FROM device_requests WHERE expires_at <= ? AND state IN ('pending', 'claimed', 'cancel_requested') ORDER BY expires_at LIMIT 1000",
            (iso_millis(current),),
        ).fetchall()
        recovered = 0
        for row in rows:
            with self.store.transaction():
                event = "expire" if row["state"] == "pending" else "recover_outcome_unknown"
                self.store.database.execute(
                    "UPDATE device_requests SET state = ?, parameters_json = '' WHERE request_id = ?",
                    (next_device_request_state(row["state"], event), row["request_id"]),
                )
                recovered += 1
        return recovered

    def cancel(self, request_id: str, device_id: str, pairing_generation: int, grant_revision: int, correlation_id: str, now: datetime | str | None = None) -> dict[str, Any]:
        current = _now(now)
        expired = False
        record: dict[str, Any] | None = None
        with self.store.transaction():
            row = self._row(request_id)
            self._assert_binding(row, device_id, pairing_generation, grant_revision)
            if self._expire_if_due(row, current):
                expired = True
            else:
                next_state = next_device_request_state(row["state"], "cancel")
                self.store.database.execute("UPDATE device_requests SET state = ?, parameters_json = CASE WHEN ? = 'cancelled' THEN '' ELSE parameters_json END WHERE request_id = ?", (next_state, next_state, request_id))
                self.events.append("device.request.cancel.requested", correlation_id, {"requestId": request_id}, current)
                record = self.get(request_id)
        if expired:
            raise GatewayError("OUTCOME_UNKNOWN")
        if record is None:
            raise GatewayError("OUTCOME_UNKNOWN")
        return record

    def revoke_for_device(
        self, device_id: str, correlation_id: str, now: datetime | str | None = None,
    ) -> int:
        """Takes every live request of one device out of the queue (§13).

        Only the documented `cancel` transition is used, so a request that the
        device had already claimed becomes `cancel_requested` rather than a
        fabricated outcome. What finishes the job is the caller's
        `pairingGeneration` bump: every row left behind is then bound to a
        generation the device can no longer present, so it can never be claimed
        or answered (contract §12, `PAIRING_GENERATION_STALE`).
        """
        current = _now(now)
        revoked = 0
        with self.store.transaction():
            rows = self.store.database.execute(
                "SELECT request_id, state FROM device_requests "
                "WHERE device_id = ? AND state IN ('pending', 'claimed', 'cancel_requested')",
                (device_id,),
            ).fetchall()
            for row in rows:
                self.store.database.execute(
                    "UPDATE device_requests SET state = ?, parameters_json = '' WHERE request_id = ?",
                    (next_device_request_state(row["state"], "cancel"), row["request_id"]),
                )
                self.events.append(
                    "device.request.cancel.requested", correlation_id,
                    {"requestId": row["request_id"]}, current,
                )
                revoked += 1
        return revoked

    revokeForDevice = revoke_for_device

    def get(self, request_id: str) -> dict[str, Any]:
        row = self._row(request_id)
        return self._map(row)

    def list(self) -> list[dict[str, Any]]:
        rows = self.store.database.execute("SELECT * FROM device_requests ORDER BY request_id").fetchall()
        return [self._map(row) for row in rows]

    def _map(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "requestId": row["request_id"], "deviceId": row["device_id"],
            "pairingGeneration": int(row["pairing_generation"]), "grantRevision": int(row["grant_revision"]),
            "risk": row["risk"], "state": row["state"],
            "capability": json.loads(row["capability_json"]),
            "provider": json.loads(row["provider_json"]),
            "parameters": {} if row["parameters_json"] == "" else self.store.open_json(
                row["parameters_json"],
                f"device-request:{self.account_id}:{row['request_id']}:parameters",
            ),
            "createdAt": row["created_at"], "expiresAt": row["expires_at"],
            "requiresForegroundConfirmation": bool(row["requires_foreground_confirmation"]),
        }

    def _row(self, request_id: str) -> sqlite3.Row:
        row = self.store.database.execute("SELECT * FROM device_requests WHERE request_id = ?", (request_id,)).fetchone()
        if row is None:
            raise GatewayError("OUTCOME_UNKNOWN")
        return row

    @staticmethod
    def _assert_binding(row: sqlite3.Row, device_id: str, pairing_generation: int, grant_revision: int) -> None:
        if row["device_id"] != device_id or int(row["pairing_generation"]) != pairing_generation:
            raise GatewayError("PAIRING_GENERATION_STALE")
        if int(row["grant_revision"]) != grant_revision:
            raise GatewayError("GRANT_STALE")

    def _expire_if_due(self, row: sqlite3.Row, current: datetime) -> bool:
        if _now(row["expires_at"]) > current or row["state"] not in {"pending", "claimed", "cancel_requested"}:
            return False
        event = "expire" if row["state"] == "pending" else "recover_outcome_unknown"
        self.store.database.execute(
            "UPDATE device_requests SET state = ?, parameters_json = '' WHERE request_id = ?",
            (next_device_request_state(row["state"], event), row["request_id"]),
        )
        return True

    def _receipt(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "claimId": row["claim_id"], "requestId": row["request_id"], "accountId": self.account_id,
            "deviceId": row["device_id"], "pairingGeneration": int(row["pairing_generation"]),
            "grantRevision": int(row["grant_revision"]),
        }

    submitResult = submit_result
    validateClaimReplay = validate_claim_replay
    validateResultReplay = validate_result_replay
    recoverExpired = recover_expired


class ConversationPort:
    def __init__(
        self, account_id: str, store: AccountStore, attachments: AttachmentStore,
        audit: AuditStore, events: EventStore, policy: AttachmentPolicy | None = None,
    ):
        self.account_id = account_id
        self.store = store
        self.attachments = attachments
        self.audit = audit
        self.events = events
        self.policy = policy or DEFAULT_ATTACHMENT_POLICY

        self.history_reader: Any = None
        from .conversation_workflow import ConversationWorkflow
        self.workflow = ConversationWorkflow(self)

    def create(self, client_conversation_id: str, title: str | None, correlation_id: str, now: datetime | str | None = None) -> dict[str, Any]:
        current = _now(now)
        conversation_id = f"conv_{uuid.uuid4()}"
        with self.store.transaction():
            self.store.database.execute(
                "INSERT INTO conversations(conversation_id, client_conversation_id, title, created_at) VALUES (?, ?, ?, ?)",
                (conversation_id, client_conversation_id, title, iso_millis(current)),
            )
            self.audit.append(
                "conversation.created", {"accountId": self.account_id},
                {"conversationId": conversation_id, "clientConversationId": client_conversation_id},
                correlation_id, current,
            )
        return {"conversationId": conversation_id, "clientConversationId": client_conversation_id, "title": title}

    def accept_message(
        self, conversation_id: str, client_message_id: str, text: str,
        attachment_ids: list[str], device_id: str, request_id: str,
        correlation_id: str, now: datetime | str | None = None,
        dispatch_to_agent: bool = True,
        emit_queued: bool = True,
    ) -> dict[str, Any]:
        current = _now(now)
        for attachment_id in attachment_ids:
            self.attachments.require_verified_for_message(attachment_id, current)
        with self.store.transaction():
            row = self.store.database.execute("SELECT conversation_id FROM conversations WHERE conversation_id = ?", (conversation_id,)).fetchone()
            if row is None:
                raise GatewayError("SCHEMA_INVALID")
            prior = self.store.database.execute("SELECT message_id,text,attachment_ids_json FROM messages WHERE conversation_id=? AND client_message_id=?", (conversation_id,client_message_id)).fetchone()
            receipt_key = f"message-receipt:{conversation_id}:{client_message_id}"
            fingerprint = hashlib.sha256(_jcs({"text":text,"attachments":attachment_ids,"deviceId":device_id}).encode()).hexdigest()
            if prior:
                saved = self.store.database.execute("SELECT value FROM account_metadata WHERE key=?",(receipt_key,)).fetchone()
                if not saved or saved[0] != fingerprint: raise GatewayError("IDEMPOTENCY_CONFLICT")
                generation = self.workflow.for_message(prior["message_id"])
                return {"status":"accepted","messageId":prior["message_id"],"conversationId":conversation_id,**({"generationId":generation["generationId"]} if generation else {})}
            message_id = f"msg_{uuid.uuid4()}"
            self.store.database.execute("INSERT INTO account_metadata(key,value) VALUES (?,?)",(receipt_key,fingerprint))
            self.store.database.execute(
                """
                INSERT INTO messages(
                    message_id, conversation_id, client_message_id, sender, text,
                    created_at, attachment_ids_json, state
                ) VALUES (?, ?, ?, 'user', ?, ?, ?, 'CONFIRMED')
                """,
                (message_id, conversation_id, client_message_id, self.store.seal_json(text, f"message:{message_id}:text"), iso_millis(current), _json(attachment_ids)),
            )
            device = self.store.database.execute("SELECT pairing_generation,grant_revision FROM device_keys WHERE device_id=?",(device_id,)).fetchone()
            origin = {"deviceId":device_id,"pairingGeneration":int(device[0]) if device else 1,"grantRevision":int(device[1]) if device else 1,"conversationId":conversation_id,"messageId":message_id,"clientMessageId":client_message_id}
            for identity in (message_id,client_message_id):
                self.store.database.execute("INSERT OR REPLACE INTO account_metadata(key,value) VALUES (?,?)",(f"message-device:{identity}",_jcs(origin)))
            self.audit.append(
                "conversation.message.accepted", {"accountId": self.account_id, "deviceId": device_id},
                {"conversationId": conversation_id, "messageId": message_id, "attachmentCount": len(attachment_ids)},
                correlation_id, current,
            )
            generation_id = self.workflow.register({"messageId":message_id,"conversationId":conversation_id},device_id,iso_millis(current)) if dispatch_to_agent else None
            if dispatch_to_agent:
                self.store.database.execute(
                    """
                    INSERT INTO conversation_message_dispatch(
                      message_id, conversation_id, client_message_id, request_id,
                      status, revision, error_code, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, 'queued', 0, NULL, ?, ?)
                    """,
                    (
                        message_id, conversation_id, client_message_id, request_id,
                        iso_millis(current), iso_millis(current),
                    ),
                )
                if emit_queued: self.events.append(
                    "conversation.message.status", correlation_id,
                    {
                        "conversationId": conversation_id,
                        "messageId": message_id,
                        "clientMessageId": client_message_id,
                        "status": "queued",
                        "revision": 0,
                        "errorCode": None,
                        "generationId": generation_id,
                    },
                    current,
                )
            return {"status": "accepted", "messageId": message_id, "conversationId": conversation_id, **({"generationId":generation_id} if generation_id else {})}

    def dispatch_message(self, client_message_id: str) -> dict[str, Any] | None:
        """Read the persisted message and ordered attachment metadata for Hermes."""
        row = self.store.database.execute(
            """
            SELECT m.message_id, m.conversation_id, m.client_message_id, m.text,
                   m.created_at, m.attachment_ids_json, d.status, d.revision,
                   d.claim_token, d.claim_until
            FROM messages AS m
            JOIN conversation_message_dispatch AS d ON d.message_id = m.message_id
            WHERE m.client_message_id = ? AND m.sender = 'user'
            ORDER BY m.created_at DESC LIMIT 1
            """,
            (client_message_id,),
        ).fetchone()
        if row is None:
            return None
        try:
            attachment_ids = json.loads(str(row["attachment_ids_json"]))
        except (TypeError, ValueError, json.JSONDecodeError):
            raise GatewayError("SCHEMA_INVALID")
        if not isinstance(attachment_ids, list) or any(not isinstance(item, str) for item in attachment_ids):
            raise GatewayError("SCHEMA_INVALID")
        attachments = []
        for attachment_id in attachment_ids:
            attachment = self.attachments.get_record(attachment_id)
            attachments.append({
                "attachmentId": attachment_id,
                "filename": attachment["filename"],
                "mediaType": attachment["mediaType"],
                "sizeBytes": attachment["sizeBytes"],
                "sha256": attachment["sha256"],
                "state": str(attachment["state"]),
            })
        return {
            "messageId": str(row["message_id"]),
            "conversationId": str(row["conversation_id"]),
            "clientMessageId": str(row["client_message_id"]),
            "text": self.workflow.aggregate(str(row["message_id"]),self.store.open_json(row["text"], f"message:{row['message_id']}:text") if row["text"] else "") if row["status"] == "queued" else "",
            "createdAt": str(row["created_at"]),
            "attachmentIds": attachment_ids,
            "attachments": attachments,
            "status": str(row["status"]),
            "revision": int(row["revision"]),
            "claimUntil": str(row["claim_until"]) if row["claim_until"] else None,
        }

    def claim_dispatch(
        self, client_message_id: str, now: datetime | str | None = None,
    ) -> dict[str, Any] | None:
        """Atomically lease one queued message to a single Hermes dispatcher."""
        current = _now(now)
        lease_until = iso_millis(current + timedelta(seconds=MESSAGE_DISPATCH_LEASE_SECONDS))
        token = f"dclaim_{uuid.uuid4()}"
        with self.store.transaction():
            row = self.store.database.execute(
                "SELECT message_id, status, claim_token, claim_until FROM conversation_message_dispatch "
                "WHERE client_message_id = ? ORDER BY created_at DESC LIMIT 1",
                (client_message_id,),
            ).fetchone()
            if row is None or row["status"] != "queued":
                return None
            if row["claim_token"] and row["claim_until"] and _now(row["claim_until"]) > current:
                return None
            if row["claim_token"]:
                # An expired lease cannot prove that the native turn stopped.
                self.workflow.settle(str(row['message_id']),'unknown')
                self.store.database.execute("UPDATE conversation_message_dispatch SET claim_token=NULL,claim_until=NULL WHERE message_id=?",(row['message_id'],))
                return None
            if not self.workflow.claim(str(row["message_id"])): return None
            cursor = self.store.database.execute(
                """
                UPDATE conversation_message_dispatch
                SET claim_token = ?, claim_until = ?
                WHERE message_id = ? AND status = 'queued'
                  AND (claim_token IS NULL OR claim_until IS NULL OR claim_until <= ?)
                """,
                (token, lease_until, row["message_id"], iso_millis(current)),
            )
            if cursor.rowcount != 1:
                return None
        dispatch = self.dispatch_message(client_message_id)
        if dispatch is not None:
            dispatch["claimToken"] = token
        return dispatch

    def update_dispatch_status(
        self, message_id: str, status: str, error_code: str | None,
        correlation_id: str, now: datetime | str | None = None,
        *, claim_token: str | None = None, force: bool = False,
    ) -> dict[str, Any]:
        """Persist one monotonic Agent delivery status and its SSE event."""
        allowed_errors = {
            "AGENT_UNAVAILABLE", "ATTACHMENT_READ_FAILED", "AGENT_MEDIA_REJECTED",
            "MODEL_REQUEST_REJECTED",
        }
        if status not in {"delivered", "completed", "failed"}:
            raise GatewayError("SCHEMA_INVALID")
        if (status == "failed" and error_code not in allowed_errors) or (status != "failed" and error_code is not None):
            raise GatewayError("SCHEMA_INVALID")
        current = _now(now)
        with self.store.transaction():
            row = self.store.database.execute(
                "SELECT * FROM conversation_message_dispatch WHERE message_id = ?",
                (message_id,),
            ).fetchone()
            if row is None:
                raise GatewayError("SCHEMA_INVALID")
            previous = str(row["status"])
            if previous == status:
                return {"status": previous, "revision": int(row["revision"]), "errorCode": row["error_code"]}
            transitions = {
                "queued": {"delivered", "failed"},
                "delivered": {"completed", "failed"},
                "completed": set(),
                "failed": set(),
            }
            if status not in transitions.get(previous, set()):
                raise GatewayError("INVALID_STATE_TRANSITION")
            if previous == "queued" and status == "delivered":
                if not claim_token or row["claim_token"] != claim_token:
                    raise GatewayError("INVALID_STATE_TRANSITION")
            if (
                previous == "queued" and status == "failed"
                and row["claim_token"] and row["claim_token"] != claim_token and not force
            ):
                raise GatewayError("INVALID_STATE_TRANSITION")
            revision = int(row["revision"]) + 1
            self.store.database.execute(
                "UPDATE conversation_message_dispatch SET status = ?, revision = ?, error_code = ?, claim_token = NULL, claim_until = NULL, updated_at = ? WHERE message_id = ?",
                (status, revision, error_code, iso_millis(current), message_id),
            )
            payload = {
                "conversationId": str(row["conversation_id"]),
                "messageId": message_id,
                "clientMessageId": str(row["client_message_id"]),
                "status": status,
                "revision": revision,
                "errorCode": error_code,
            }
            generation = self.workflow.for_message(message_id)
            if generation:
                payload["generationId"] = generation["generationId"]
                if status in {"completed","failed"}: self.workflow.settle(message_id,status)
                for member_id in generation["messageIds"]:
                    if member_id == message_id: continue
                    member = self.store.database.execute("SELECT client_message_id FROM messages WHERE message_id=?",(member_id,)).fetchone()
                    self.events.append("conversation.message.status",correlation_id,{**payload,"messageId":member_id,"clientMessageId":member[0]},current)
            self.events.append("conversation.message.status", correlation_id, payload, current)
            return {"status": status, "revision": revision, "errorCode": error_code}

    def incomplete_dispatches(self) -> list[dict[str, Any]]:
        rows = self.store.database.execute(
            "SELECT client_message_id FROM conversation_message_dispatch WHERE status IN ('queued', 'delivered') ORDER BY created_at"
        ).fetchall()
        result = []
        for row in rows:
            item = self.dispatch_message(str(row["client_message_id"]))
            if item is not None:
                result.append(item)
        return result

    def record_assistant_message(
        self, conversation_id: str, message_id: str, text: str,
        now: datetime | str | None = None,
    ) -> dict[str, Any]:
        current = _now(now)
        if callable(self.history_reader):
            self.store.database.execute("INSERT OR REPLACE INTO account_metadata(key,value) VALUES (?,?)", (
                f"history-hash:{conversation_id}:{message_id}", hashlib.sha256(text.encode()).hexdigest(),
            ))
        with self.store.transaction():
            self.store.database.execute(
                """
                INSERT INTO messages(
                    message_id, conversation_id, client_message_id, sender, text,
                    created_at, attachment_ids_json, state
                ) VALUES (?, ?, ?, 'assistant', ?, ?, '[]', 'CONFIRMED')
                ON CONFLICT(message_id) DO UPDATE SET text = excluded.text
                WHERE messages.sender = 'assistant'
                """,
                (message_id, conversation_id, message_id, "" if callable(self.history_reader) else self.store.seal_json(text, f"message:{message_id}:text"), iso_millis(current)),
            )
            return {"status": "recorded", "messageId": message_id, "conversationId": conversation_id}

    def list_messages(
        self, conversation_id: str, client_message_id: str | None = None,
        cursor: str | None = None, limit: int = 50,
    ) -> dict[str, Any]:
        if callable(self.history_reader):
            from .host_history import host_history_page
            return host_history_page(self, conversation_id, client_message_id, cursor, limit)
        row = self.store.database.execute(
            "SELECT conversation_id FROM conversations WHERE conversation_id = ?",
            (conversation_id,),
        ).fetchone()
        if row is None:
            raise GatewayError("SCHEMA_INVALID")
        revision_row = self.store.database.execute(
            "SELECT value FROM account_metadata WHERE key = ?",
            (f"conversation_revision:{conversation_id}",),
        ).fetchone()
        revision = int(revision_row[0]) if revision_row else 1
        page_limit = max(1, min(int(limit), 100))
        after: tuple[str, str] | None = None
        upper_rowid = int(self.store.database.execute(
            "SELECT COALESCE(MAX(rowid), 0) FROM messages WHERE conversation_id = ?", (conversation_id,),
        ).fetchone()[0])
        if cursor:
            try:
                saved = self.store.open_json(cursor, f"timeline-cursor:{conversation_id}")
                if (not isinstance(saved, dict) or set(saved) != {"revision", "through", "createdAt", "messageId"}
                    or not isinstance(saved["revision"], int) or not isinstance(saved["through"], int)
                    or not isinstance(saved["createdAt"], str) or not isinstance(saved["messageId"], str)):
                    raise ValueError("invalid cursor")
                if saved["revision"] != revision:
                    raise GatewayError("CURSOR_EXPIRED", {"recoverableResources": ["conversations"]})
                upper_rowid = saved["through"]
                after = (saved["createdAt"], saved["messageId"])
            except GatewayError as error:
                if error.code == "CURSOR_EXPIRED":
                    raise
                raise GatewayError("SCHEMA_INVALID") from error
            except (ValueError, KeyError, TypeError) as error:
                raise GatewayError("SCHEMA_INVALID") from error
        query = (
            "SELECT message_id, conversation_id, client_message_id, sender, text, "
            "created_at, attachment_ids_json, state FROM messages WHERE conversation_id = ? AND rowid <= ?"
        )
        params: list[Any] = [conversation_id, upper_rowid]
        if client_message_id:
            query += " AND client_message_id = ?"
            params.append(client_message_id)
        if after:
            query += " AND (created_at > ? OR (created_at = ? AND message_id > ?))"
            params.extend((after[0], after[0], after[1]))
        query += " ORDER BY created_at ASC, message_id ASC LIMIT ?"
        params.append(page_limit + 1)

        rows = self.store.database.execute(query, params).fetchall()
        has_more = len(rows) > page_limit
        rows = rows[:page_limit]
        result_messages = []
        for r in rows:
            att_ids = []
            try:
                raw_json = r["attachment_ids_json"] if hasattr(r, "keys") and "attachment_ids_json" in r.keys() else r[6]
                att_ids = json.loads(raw_json) if raw_json else []
            except Exception:
                pass

            mid = r["message_id"] if hasattr(r, "keys") and "message_id" in r.keys() else r[0]
            cid = r["conversation_id"] if hasattr(r, "keys") and "conversation_id" in r.keys() else r[1]
            cmid = r["client_message_id"] if hasattr(r, "keys") and "client_message_id" in r.keys() else r[2]
            sender = r["sender"] if hasattr(r, "keys") and "sender" in r.keys() else r[3]
            txt = r["text"] if hasattr(r, "keys") and "text" in r.keys() else r[4]
            txt = self.store.open_json(txt, f"message:{mid}:text")
            created = r["created_at"] if hasattr(r, "keys") and "created_at" in r.keys() else r[5]
            st = r["state"] if hasattr(r, "keys") and "state" in r.keys() else r[7]

            parts = []
            if txt:
                parts.append({"type": "text", "text": txt})
            for aid in att_ids:
                part_dict: dict[str, Any] = {"type": "attachment", "attachmentId": aid}
                try:
                    att_obj = self.attachments.get_record(aid)
                    if att_obj:
                        part_dict["filename"] = att_obj.get("filename") or ""
                        part_dict["mediaType"] = att_obj.get("mediaType") or ""
                        part_dict["sizeBytes"] = att_obj.get("sizeBytes") or 0
                except Exception:
                    pass
                parts.append(part_dict)

            ts = 0
            try:
                ts = _epoch_millis(created)
            except Exception:
                pass
            if ts <= 0:
                ts = _epoch_millis(_now())

            result_messages.append({
                "messageId": mid,
                "clientMessageId": cmid,
                "conversationId": cid,
                "sender": sender or "assistant",
                "text": txt or "",
                "parts": parts,
                "timestamp": ts,
                "state": st or "CONFIRMED",
                "createdAt": created,
            })
        next_cursor = None
        if has_more and rows:
            next_cursor = self.store.seal_json({
                "revision": revision, "through": upper_rowid,
                "createdAt": rows[-1]["created_at"], "messageId": rows[-1]["message_id"],
            }, f"timeline-cursor:{conversation_id}")
        return {"messages": result_messages, "nextCursor": next_cursor, "snapshotRevision": revision}

    def list(self) -> list[dict[str, Any]]:
        rows = self.store.database.execute("SELECT conversation_id, client_conversation_id, title FROM conversations ORDER BY conversation_id").fetchall()
        return [{"conversationId": r[0], "clientConversationId": r[1], "title": r[2]} for r in rows]

    def get(self, conversation_id: str) -> dict[str, Any]:
        row = self.store.database.execute(
            "SELECT conversation_id, client_conversation_id, title FROM conversations WHERE conversation_id = ?",
            (conversation_id,),
        ).fetchone()
        if row is None:
            raise GatewayError("SCHEMA_INVALID")
        return {"conversationId": row[0], "clientConversationId": row[1], "title": row[2]}

    def update_title(
        self, conversation_id: str, title: str, correlation_id: str,
        now: datetime | str | None = None,
    ) -> dict[str, Any]:
        current = _now(now)
        with self.store.transaction():
            row = self.store.database.execute(
                "SELECT conversation_id, client_conversation_id, title FROM conversations WHERE conversation_id = ?",
                (conversation_id,),
            ).fetchone()
            if row is None:
                raise GatewayError("SCHEMA_INVALID")
            self.store.database.execute(
                "UPDATE conversations SET title = ? WHERE conversation_id = ?",
                (title, conversation_id),
            )
            self.audit.append(
                "conversation.title.updated",
                {"accountId": self.account_id},
                {"conversationId": conversation_id, "title": title},
                correlation_id,
                current,
            )
        return {"conversationId": conversation_id, "clientConversationId": row[1], "title": title}

    acceptMessage = accept_message


class GatewayAccount:
    def __init__(
        self, account_id: str, paths: AccountPaths, store: AccountStore,
        contracts: ContractRegistry | None = None,
        attachment_policy: AttachmentPolicy | None = None,
        credential_verifier: Any = None,
    ):
        self.account_id = account_id
        self.accountId = account_id
        self.paths = paths
        self.store = store
        self.master_key_ref = str(store.database.execute("SELECT value FROM account_metadata WHERE key = 'master_key_ref'").fetchone()[0])
        self.masterKeyRef = self.master_key_ref
        self.audit = AuditStore(store, account_id)
        self.events = EventStore(store, contracts)
        self.attachment_policy = attachment_policy or DEFAULT_ATTACHMENT_POLICY
        self.attachments = AttachmentStore(
            account_id, paths, store, self.audit, self.attachment_policy, self.events
        )
        self.device_requests = DeviceRequestStore(account_id, store, self.audit, self.events, contracts)
        self.conversations = ConversationPort(
            account_id, store, self.attachments, self.audit, self.events, self.attachment_policy,
        )
        self.agent_sessions = AgentSessionBindings(store)
        self.approvals = ApprovalRequests(store)
        self.credentials = CredentialStore(store)
        self.sessions = SessionService(account_id, store, self.audit, self.events, credential_verifier)
        self.deviceRequests = self.device_requests
        self.agentSessions = self.agent_sessions
        self.approvalRequests = self.approvals
        self.masterKeyRef = self.master_key_ref
        self._closed = False

    def pairing_generation(self) -> int:
        row = self.store.database.execute(
            "SELECT value FROM account_metadata WHERE key = 'pairing_generation'"
        ).fetchone()
        return int(row[0]) if row is not None else 1

    pairingGeneration = pairing_generation

    def revoke_pairing(
        self, device_id: str, correlation_id: str, now: datetime | str | None = None,
    ) -> dict[str, Any]:
        """Ends one device pairing: contract section 13 (`:798`) plus D1.

        Revokes the five items the contract names — device key, refresh
        credential, grants, queue, unconfirmed attachments — and every access
        session of the device, then raises `pairingGeneration` so every record
        still bound to the old one is fenced.

        Each boolean in the answer is a post-condition measured after the write,
        not a claim that work was attempted: `True` means this category holds
        nothing live for the device any more. A replay therefore answers the
        same terminal state instead of re-running a destructive sweep.

        `PAIRING_REQUIRED` is raised when the device has no registered key: an
        endpoint that destroys a pairing must refuse rather than report success
        for a pairing that does not exist.
        """
        current = _now(now)
        with self.store.transaction():
            paired = self.store.database.execute(
                "SELECT pairing_generation FROM device_keys WHERE device_id = ?", (device_id,)
            ).fetchone()
            if paired is None:
                raise GatewayError("PAIRING_REQUIRED", {"deviceId": device_id})
            pairing_generation = int(paired["pairing_generation"])
            self.sessions.revoke_device_keys(device_id, correlation_id, current)
            self.sessions.revoke_refresh_credentials(device_id, correlation_id, current)
            self.sessions.revoke_device_sessions(device_id, correlation_id, current)
            self.device_requests.revoke_for_device(device_id, correlation_id, current)
            self.attachments.revoke_unconfirmed(device_id, pairing_generation, correlation_id, current)
            next_generation = self.pairing_generation() + 1
            self.store.database.execute(
                "UPDATE account_metadata SET value = ? WHERE key = 'pairing_generation'",
                (str(next_generation),),
            )
            self.audit.append(
                "pairing.revoked",
                {"accountId": self.account_id, "deviceId": device_id},
                {"pairingGeneration": next_generation}, correlation_id, current,
            )
        return {
            "deviceId": device_id,
            # No key row survives, so nothing can sign as this device and no
            # grant can be presented: this schema's per-device grant state is
            # the `grant_revision` carried by that row (see 3-6 for the store
            # that gives grants a table of their own).
            "deviceKeysRevoked": self._device_key_count(device_id) == 0,
            "refreshRevoked": self.sessions.active_refresh_credential_count(device_id) == 0,
            "grantsRevoked": self._device_key_count(device_id) == 0,
            "deviceRequestsRevoked": self._live_device_request_count(device_id) == 0,
            "unconfirmedAttachmentsRevoked": self._unconfirmed_attachment_count(device_id, pairing_generation) == 0,
            "sessionsRevoked": self._active_session_count(device_id) == 0,
        }

    revokePairing = revoke_pairing

    def bump_grant_revision(
        self, device_id: str, correlation_id: str, now: datetime | str | None = None, grant_digest: str | None = None,
    ) -> dict[str, Any]:
        """Raises one pairing's `grantRevision` by one (contract section 11).

        The revision is the monotone counter a device presents with every
        device request (`:702`), so after the Android-local grant has changed
        the Gateway must move the device's revision before any request bound to
        the old one can still be claimed or answered (`:782`, `GRANT_STALE`).

        One commit carries all three facts: the new revision on the device key
        row, the audit entry, and the `pairing.grant.changed` event on the
        stream. The event is a notification only — its payload is exactly
        `$defs/pairingGrantChangedPayload`, and this host has no signed-grant
        mechanism, so the optional `grantDigest` (the signed-grant digest of
        `:782`) and the plugin-identity fields are omitted rather than invented.
        """
        current = _now(now)
        with self.store.transaction():
            row = self.store.database.execute(
                "SELECT grant_revision FROM device_keys WHERE device_id = ?", (device_id,)
            ).fetchone()
            if row is None:
                raise GatewayError("PAIRING_REQUIRED", {"deviceId": device_id})
            next_revision = int(row["grant_revision"]) + 1
            self.store.database.execute(
                "UPDATE device_keys SET grant_revision = ? WHERE device_id = ?",
                (next_revision, device_id),
            )
            self.events.append(
                "pairing.grant.changed", correlation_id, {"deviceId": device_id, "grantRevision": next_revision, **({"grantDigest":grant_digest} if grant_digest else {})}, current,
            )
            self.audit.append(
                "pairing.grant.changed",
                {"accountId": self.account_id, "deviceId": device_id},
                {"deviceId": device_id, "grantRevision": next_revision},
                correlation_id, current,
            )
        return {"deviceId": device_id, "grantRevision": next_revision}

    bumpGrantRevision = bump_grant_revision

    def _device_key_count(self, device_id: str) -> int:
        return int(self.store.database.execute(
            "SELECT COUNT(*) FROM device_keys WHERE device_id = ?", (device_id,)
        ).fetchone()[0])

    def _active_session_count(self, device_id: str) -> int:
        return int(self.store.database.execute(
            "SELECT COUNT(*) FROM access_sessions WHERE device_id = ? AND status = 'active'", (device_id,)
        ).fetchone()[0])

    def _live_device_request_count(self, device_id: str) -> int:
        return int(self.store.database.execute(
            "SELECT COUNT(*) FROM device_requests WHERE device_id = ? "
            "AND state IN ('pending', 'claimed', 'cancel_requested')", (device_id,)
        ).fetchone()[0])

    def _unconfirmed_attachment_count(
        self, device_id: str | None = None, pairing_generation: int | None = None,
    ) -> int:
        if (device_id is None) != (pairing_generation is None):
            raise ValueError("device and pairing generation must be supplied together")
        query = "SELECT COUNT(*) FROM attachments WHERE acknowledged_at IS NULL AND state != 'deleted'"
        parameters: tuple[Any, ...] = ()
        if device_id is not None:
            query += " AND owner_device_id = ? AND owner_pairing_generation = ?"
            parameters = (device_id, pairing_generation)
        return int(self.store.database.execute(query, parameters).fetchone()[0])

    def close(self) -> None:
        if not self._closed:
            self.store.close()
            self._closed = True


class SessionService:
    def __init__(
        self, account_id: str, store: AccountStore, audit: AuditStore,
        events: EventStore, credential_verifier: Any = None,
    ):
        self.account_id = account_id
        self.store = store
        self.audit = audit
        # Injected like DeviceRequestStore's `events`: revocation is a fact the
        # event stream must carry (contract section 9), so the session service
        # cannot rely on its caller to forward one.
        self.events = events
        self.credential_verifier = credential_verifier

    @staticmethod
    def _digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _secret(prefix: str) -> str:
        return f"{prefix}_{secrets.token_urlsafe(32)}"

    def create_password_session(
        self, username: str, password: str, installation: Mapping[str, Any],
        correlation_id: str, now: datetime | str | None = None,
    ) -> dict[str, Any]:
        installation_id = installation.get("installationId") if isinstance(installation, Mapping) else None
        device_public_key = installation.get("devicePublicKey") if isinstance(installation, Mapping) else None
        if (
            not isinstance(username, str) or not username
            or not isinstance(password, str) or not password
            or not isinstance(installation_id, str) or not installation_id
            or not canonical_device_key(device_public_key)
            or self.credential_verifier is None
        ):
            raise GatewayError("AUTHENTICATION_FAILED")
        credentials = CredentialStore(self.store)
        credential_digest = credentials.password_digest()
        verifier = getattr(self.credential_verifier, "verify", self.credential_verifier)
        try:
            verified = verifier(self.account_id, username, password, installation)
        except Exception as exc:
            raise GatewayError("AUTHENTICATION_FAILED") from exc
        if verified is not True:
            raise GatewayError("AUTHENTICATION_FAILED")
        current = _now(now)
        with self.store.transaction():
            # Compare under the same write lock as issuance: reset must fence
            # in-flight old verification, including a missing->present digest.
            if credentials.password_digest() != credential_digest:
                raise GatewayError("AUTHENTICATION_FAILED")
            bundle = self._issue(installation_id, f"dev_{uuid.uuid4()}", current)
            self._register_device_key(bundle["deviceId"], installation_id, device_public_key, current)
            self.audit.append(
                "session.password.created",
                {"accountId": self.account_id, "deviceId": bundle["deviceId"], "installationId": installation_id},
                {"method": "password", "displayName": installation.get("displayName")}, correlation_id, current,
            )
            return bundle

    def refresh(
        self, refresh_credential: str, installation_id: str, device_id: str,
        correlation_id: str, now: datetime | str | None = None,
    ) -> dict[str, Any]:
        current = _now(now)
        reused = False
        bundle: dict[str, Any] | None = None
        with self.store.transaction():
            digest = self._digest(refresh_credential)
            row = self.store.database.execute(
                "SELECT * FROM refresh_credentials WHERE credential_hash = ?", (digest,)
            ).fetchone()
            if row is None or row["installation_id"] != installation_id or row["device_id"] != device_id:
                raise GatewayError("AUTHENTICATION_FAILED")
            if row["status"] != "active":
                self.store.database.execute(
                    "UPDATE refresh_credentials SET status = 'revoked' WHERE installation_id = ? AND device_id = ?",
                    (installation_id, device_id),
                )
                self.audit.append(
                    "session.refresh.reused",
                    {"accountId": self.account_id, "deviceId": device_id, "installationId": installation_id},
                    {"reused": True}, correlation_id, current,
                )
                reused = True
            else:
                bundle = self._issue(installation_id, device_id, current)
                self.store.database.execute(
                    "UPDATE refresh_credentials SET status = 'used', replaced_by_hash = ? WHERE credential_hash = ?",
                    (self._digest(bundle["refreshCredential"]), digest),
                )
                self.audit.append(
                    "session.refresh.rotated",
                    {"accountId": self.account_id, "deviceId": device_id, "installationId": installation_id},
                    {"rotated": True}, correlation_id, current,
                )
        if reused:
            raise GatewayError("REFRESH_REUSED")
        if bundle is None:
            raise GatewayError("AUTHENTICATION_FAILED")
        return bundle

    def register_device_key(
        self, device_id: str, installation_id: str, public_key: str,
        now: datetime | str | None = None,
    ) -> None:
        self._register_device_key(device_id, installation_id, public_key, _now(now))

    def _register_device_key(self, device_id: str, installation_id: str, public_key: str, current: datetime) -> None:
        """Binds the Ed25519 public key a device proved at login.

        The key is the only thing that makes a later request signature
        checkable, so it is written in the same transaction that issues the
        session: a session whose key was never recorded cannot be used.
        """
        self.store.database.execute(
            "INSERT INTO device_keys(device_id, installation_id, public_key, pairing_generation, grant_revision, registered_at) "
            "VALUES (?, ?, ?, ?, 1, ?) "
            "ON CONFLICT(device_id) DO UPDATE SET "
            "installation_id = excluded.installation_id, public_key = excluded.public_key, registered_at = excluded.registered_at",
            (device_id, installation_id, public_key, int((self.store.database.execute("SELECT value FROM account_metadata WHERE key='pairing_generation'").fetchone() or [1])[0]), iso_millis(current)),
        )

    def resolve_session(
        self, access_token: str, session_id: str, device_id: str,
        now: datetime | str | None = None,
    ) -> dict[str, Any] | None:
        """The verified-request facts behind one live access session.

        Returns None instead of raising: the caller is an authentication seam
        that must fail closed without distinguishing "no such session" from
        "expired" to the requester.
        """
        row = self.store.database.execute(
            "SELECT s.session_id AS session_id, s.installation_id AS installation_id, s.status AS status, "
            "s.expires_at AS expires_at, k.public_key AS public_key, "
            "k.pairing_generation AS pairing_generation, k.grant_revision AS grant_revision "
            "FROM access_sessions s LEFT JOIN device_keys k ON k.device_id = s.device_id "
            "WHERE s.session_id = ? AND s.device_id = ? AND s.access_token_hash = ?",
            (session_id, device_id, self._digest(access_token)),
        ).fetchone()
        if row is None or row["status"] != "active" or _now(row["expires_at"]) <= _now(now):
            return None
        public_key = row["public_key"]
        if not isinstance(public_key, str) or not public_key:
            return None
        return {
            "sessionId": str(row["session_id"]),
            "installationId": str(row["installation_id"]),
            "devicePublicKey": public_key,
            "pairingGeneration": int(row["pairing_generation"] or 1),
            "grantRevision": int(row["grant_revision"] or 1),
        }

    def revoke_refresh_credentials(
        self, device_id: str, correlation_id: str, now: datetime | str | None = None,
    ) -> int:
        """Ends the login: the device can no longer mint a session without a password.

        Contract section 13 (`docs/contracts/gateway-protocol-v2.md:796`) is
        explicit that logging out revokes the refresh credential and does *not*
        delete the pairing. The device key stays registered so the pairing it
        proves survives the logout; deleting `device_keys` here would silently
        turn a logout into an unpair, which is a separate act with its own
        endpoint (`:798`, `DELETE /pairings/current`).

        Returns how many credentials this call moved out of the active state.
        """
        current = _now(now)
        with self.store.transaction():
            revoked = self.store.database.execute(
                "UPDATE refresh_credentials SET status = 'revoked' WHERE device_id = ? AND status = 'active'",
                (device_id,),
            ).rowcount
            self.audit.append(
                "session.refresh.revoked",
                {"accountId": self.account_id, "deviceId": device_id},
                {"revokedCount": int(revoked)}, correlation_id, current,
            )
            return int(revoked)

    revokeRefreshCredentials = revoke_refresh_credentials

    def revoke_device_keys(
        self, device_id: str, correlation_id: str, now: datetime | str | None = None,
    ) -> bool:
        """Deletes the device key of one pairing. True when a key was registered.

        Unpairing only: nothing else in the Gateway may drop the row that makes
        a device's signature checkable, because a logout that dropped it would
        be indistinguishable from destroying the pairing.
        """
        current = _now(now)
        with self.store.transaction():
            existing = self.store.database.execute(
                "SELECT 1 FROM device_keys WHERE device_id = ?", (device_id,)
            ).fetchone()
            self.store.database.execute("DELETE FROM device_keys WHERE device_id = ?", (device_id,))
            self.audit.append(
                "pairing.device_key.revoked",
                {"accountId": self.account_id, "deviceId": device_id},
                {"removed": existing is not None}, correlation_id, current,
            )
            return existing is not None

    revokeDeviceKeys = revoke_device_keys

    def revoke_device_sessions(
        self, device_id: str, correlation_id: str, now: datetime | str | None = None,
    ) -> int:
        """Ends every still-active access session of one device, not just one.

        One device holds several sessions whenever it refreshed: ending the
        pairing has to end all of them, because a session left alive would keep
        authenticating with a key the pairing no longer vouches for.
        """
        current = _now(now)
        with self.store.transaction():
            rows = self.store.database.execute(
                "SELECT session_id FROM access_sessions WHERE device_id = ? AND status = 'active'",
                (device_id,),
            ).fetchall()
            self.store.database.execute(
                "UPDATE access_sessions SET status = 'revoked' WHERE device_id = ? AND status = 'active'",
                (device_id,),
            )
            for row in rows:
                self.audit.append(
                    "session.revoked", {"accountId": self.account_id},
                    {"sessionId": row["session_id"]}, correlation_id, current,
                )
            return len(rows)

    revokeDeviceSessions = revoke_device_sessions

    def active_refresh_credential_count(self, device_id: str) -> int:
        row = self.store.database.execute(
            "SELECT COUNT(*) FROM refresh_credentials WHERE device_id = ? AND status = 'active'", (device_id,)
        ).fetchone()
        return int(row[0])

    def verify_access_token(self, access_token: str, session_id: str, device_id: str, now: datetime | str | None = None) -> bool:
        row = self.store.database.execute(
            "SELECT access_token_hash, device_id, status, expires_at FROM access_sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        return bool(
            row is not None and row["access_token_hash"] == self._digest(access_token)
            and row["device_id"] == device_id and row["status"] == "active"
            and _now(row["expires_at"]) > _now(now)
        )

    def revoke_session(self, session_id: str, correlation_id: str, now: datetime | str | None = None) -> None:
        current = _now(now)
        with self.store.transaction():
            row = self.store.database.execute(
                "SELECT device_id FROM access_sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
            self.store.database.execute("UPDATE access_sessions SET status = 'revoked' WHERE session_id = ?", (session_id,))
            self.audit.append(
                "session.revoked", {"accountId": self.account_id}, {"sessionId": session_id}, correlation_id, current,
            )
            if row is None:
                # Nothing was revoked, so the stream must not carry a fabricated
                # revocation; the audit line keeps its pre-existing behavior.
                return
            payload = {"sessionId": session_id, "deviceId": row["device_id"]}
            self.events.append("session.revoked", correlation_id, payload, current)

    def _issue(self, installation_id: str, device_id: str, current: datetime) -> dict[str, Any]:
        session_id = f"sess_{uuid.uuid4()}"
        access_token = self._secret("access")
        refresh_credential = self._secret("refresh")
        expires_at = iso_millis(current + timedelta(minutes=15))
        self.store.database.execute(
            "INSERT INTO access_sessions(session_id, installation_id, device_id, access_token_hash, status, created_at, expires_at) VALUES (?, ?, ?, ?, 'active', ?, ?)",
            (session_id, installation_id, device_id, self._digest(access_token), iso_millis(current), expires_at),
        )
        self.store.database.execute(
            "INSERT INTO refresh_credentials(credential_hash, installation_id, device_id, session_id, status, created_at, replaced_by_hash) VALUES (?, ?, ?, ?, 'active', ?, NULL)",
            (self._digest(refresh_credential), installation_id, device_id, session_id, iso_millis(current)),
        )
        return {
            "sessionId": session_id, "deviceId": device_id,
            "accessToken": access_token, "refreshCredential": refresh_credential,
            "expiresAt": expires_at,
            **dict(self.store.database.execute("SELECT pairing_generation AS pairingGeneration,grant_revision AS grantRevision FROM device_keys WHERE device_id=?",(device_id,)).fetchone() or {"pairingGeneration":1,"grantRevision":1}),
        }

    createPasswordSession = create_password_session
    activeRefreshCredentialCount = active_refresh_credential_count


_ATTACHMENT_TRANSITIONS: dict[str, dict[str, str]] = {
    "created": {"begin_upload": "uploading", "fail": "failed", "expire": "expired"},
    "uploading": {"verify": "verified", "fail": "failed", "expire": "expired"},
    "verified": {"deliver": "delivered", "fail": "failed", "expire": "expired"},
    "delivered": {"acknowledge": "acknowledged", "fail": "failed", "expire": "expired"},
    "acknowledged": {"cleanup": "deleted"},
    "failed": {"cleanup": "deleted"},
    "expired": {"cleanup": "deleted"},
    "deleted": {},
}

_DEVICE_TRANSITIONS: dict[str, dict[str, str]] = {
    "pending": {"claim": "claimed", "cancel": "cancelled", "expire": "expired"},
    "claimed": {
        "cancel": "cancel_requested", "expire": "outcome_unknown",
        "result_succeeded": "succeeded", "result_failed": "failed",
        "result_denied": "denied", "result_cancelled": "cancelled",
        "result_outcome_unknown": "outcome_unknown", "recover_outcome_unknown": "outcome_unknown",
    },
    "cancel_requested": {
        "expire": "outcome_unknown", "result_succeeded": "succeeded",
        "result_failed": "failed", "result_denied": "denied",
        "result_cancelled": "cancelled", "result_outcome_unknown": "outcome_unknown",
        "recover_outcome_unknown": "outcome_unknown",
    },
    "succeeded": {}, "failed": {}, "denied": {}, "cancelled": {},
    "expired": {}, "outcome_unknown": {},
}


def next_attachment_state(current: str, event: str) -> str:
    try:
        return _ATTACHMENT_TRANSITIONS[current][event]
    except KeyError as exc:
        raise GatewayError("INVALID_STATE_TRANSITION") from exc


def next_device_request_state(current: str, event: str) -> str:
    try:
        return _DEVICE_TRANSITIONS[current][event]
    except KeyError as exc:
        raise GatewayError("INVALID_STATE_TRANSITION") from exc


def maximum_device_request_queue_seconds(risk: str) -> int:
    if risk in {"read", "sync"}:
        return 86_400
    if risk == "write":
        return 900
    if risk == "high-privilege-ephemeral":
        return 0
    raise GatewayError("SCHEMA_INVALID")


_PERSISTABLE_ERRORS = {
    "SCHEMA_INVALID", "IDENTITY_OVERRIDE_REJECTED", "PAIRING_GENERATION_STALE",
    # D1: a refusal to unpair is a fact about the pairing, not a transient
    # failure, so a replay answers the refusal instead of sweeping again.
    "PAIRING_REQUIRED",
    "GRANT_STALE", "IDEMPOTENCY_CONFLICT", "OUTCOME_UNKNOWN", "ATTACHMENT_DIGEST_MISMATCH",
    "ATTACHMENT_EXPIRED", "MASTER_KEY_UNAVAILABLE", "MASTER_KEY_REFERENCE_MISMATCH",
    "ENCRYPTION_FAILED", "DECRYPTION_FAILED", "CURSOR_CONFLICT", "CURSOR_EXPIRED",
    # Contract §7.2: an approval answer is a deterministic fact about the
    # approval, so a refused decision is remembered rather than retried blind —
    # and the `timeout`/`withdrawn` event written alongside it stays durable
    # instead of being rolled back with the request that discovered it.
    "APPROVAL_NOT_FOUND", "APPROVAL_EXPIRED", "APPROVAL_ALREADY_RESOLVED",
    "APPROVAL_DECISION_INVALID", "APPROVAL_UNSUPPORTED",
}


COMMAND_CATALOG_FORMAT = "agent-command-catalog-1.0"

DEFAULT_COMMAND_CATALOG: tuple[dict[str, Any], ...] = (
    {
        "id": "new",
        "invocation": "/new",
        "title": "新建对话",
        "description": "结束当前会话并创建全新对话线程",
        "acceptsArguments": False,
        "availability": "available",
    },
    {
        "id": "models",
        "invocation": "/models",
        "title": "[provider]",
        "description": "切换或查看活动大模型与参数",
        "acceptsArguments": True,
        "availability": "available",
    },
    {
        "id": "status",
        "invocation": "/status",
        "title": "网关状态",
        "description": "查看当前网关连通性、时延与配对状态",
        "acceptsArguments": False,
        "availability": "available",
    },
    {
        "id": "review",
        "invocation": "/review",
        "title": "[diff]",
        "description": "审查代码变更、规范或当前文档",
        "acceptsArguments": True,
        "availability": "available",
    },
    {
        "id": "gateway",
        "invocation": "/gateway",
        "title": "<url>",
        "description": "切换或添加连接的 Agent Gateway",
        "acceptsArguments": True,
        "availability": "available",
    },
    {
        "id": "clear",
        "invocation": "/clear",
        "title": "清空时间线",
        "description": "清空当前时间线临时渲染状态",
        "acceptsArguments": False,
        "availability": "available",
    },
    {
        "id": "help",
        "invocation": "/help",
        "title": "[command]",
        "description": "查看所有可用指令与使用指南",
        "acceptsArguments": True,
        "availability": "available",
    },
)


def _contains_identity_override(value: Any) -> bool:
    if isinstance(value, Mapping):
        if any(key in {"accountId", "account_id", "deviceId", "device_id", "principalId", "principal_id", "pairingGeneration", "pairing_generation"} for key in value):
            return True
        return any(_contains_identity_override(child) for child in value.values())
    if isinstance(value, list):
        return any(_contains_identity_override(child) for child in value)
    return False


class GatewayCore:
    def __init__(
        self, storage_root: str | Path | None = None, secret_store: Any = None,
        contract_root: str | Path | None = None, commit_hook: Any = None,
        attachment_policy: AttachmentPolicy | None = None,
        credential_verifier: Any = None,
        command_catalog: Any = None,
        event_sink: EventSink | None = None,
        approval_resolver: Any = None,
        tls_spki_sha256: str | None = None,
    ):
        self.storage_root = Path(storage_root or default_hermes_gateway_root()).resolve()
        self.tls_spki_sha256 = tls_spki_sha256 if tls_spki_sha256 is not None else os.environ.get("OPEN_ANDROID_INTELLIGENCE_GATEWAY_TLS_SPKI_SHA256")
        if self.tls_spki_sha256 is not None and (re.fullmatch(r"sha256:[a-f0-9]{64}", self.tls_spki_sha256) is None or self.tls_spki_sha256 == "sha256:" + "0" * 64):
            raise ValueError("GATEWAY_TLS_IDENTITY_INVALID")
        self.secret_store = secret_store
        self.contract_root = Path(contract_root).resolve() if contract_root is not None else None
        self._contracts: ContractRegistry | None = None
        self._pending_negotiations: dict[str, dict[str, Any]] = {}
        self._admission_lock = threading.RLock()
        self._admission_window: datetime | None = None
        self._negotiation_count = 0
        self._password_attempts: dict[tuple[str, str], tuple[datetime, int]] = {}
        self._password_jobs = 0
        self.commit_hook = commit_hook
        self.attachment_policy = attachment_policy or DEFAULT_ATTACHMENT_POLICY
        self.credential_verifier = credential_verifier
        self._online_devices: dict[tuple[str,str,str], tuple[VerifiedRequestContext,int]] = {}
        self.command_catalog = tuple(command_catalog) if command_catalog is not None else DEFAULT_COMMAND_CATALOG
        self.history_reader: Any = None
        self.generation_canceller: Any = None
        self._cancel_locks: dict[tuple[str, str], tuple[Any, int]] = {}
        self._event_sinks: list[EventSink] = [event_sink] if event_sink is not None else []
        # How a decision reaches the Agent thread blocked on it. Injected by the
        # transport that owns the host runtime; without one, approval cards are
        # not a service this Gateway can actually deliver.
        self.approval_resolver = approval_resolver if callable(approval_resolver) else None

    @property
    def approval_cards_available(self) -> bool:
        """Whether interactive approval cards are a real service here (§7.2).

        A Gateway that cannot reach the host approval runtime would paint a card
        whose buttons release nothing, so the capability is advertised only when
        the resolver is present.
        """
        return self.approval_resolver is not None

    def _resolve_host_approval(self, session_key: str, choice: str, request_id: str | None) -> int | None:
        if self.approval_resolver is not None:
            try:
                resolved = self.approval_resolver(session_key, choice, request_id)
            except Exception as exc:
                logger.warning("[open_android] Approval resolver failed: %s", exc)
                return None
            return resolved if isinstance(resolved, int) else None
        return resolve_host_approval(session_key, choice, request_id)

    @property
    def contracts(self) -> ContractRegistry:
        if self._contracts is None:
            self._contracts = ContractRegistry(self.contract_root)
        return self._contracts

    def register_event_sink(self, sink: EventSink) -> None:
        """Register one transport that wants committed events as they happen.

        Registration is separate from construction because the transport starts
        after the accounts exist: an account opened before the first stream is
        still served, because delivery reads this list at call time.
        """
        if sink not in self._event_sinks:
            self._event_sinks.append(sink)

    registerEventSink = register_event_sink

    def unregister_event_sink(self, sink: EventSink) -> None:
        self._event_sinks = [item for item in self._event_sinks if item is not sink]

    unregisterEventSink = unregister_event_sink

    def deliver_event(self, account_id: str, event: Mapping[str, Any]) -> None:
        """Hand one committed event to every registered transport.

        A transport that is gone or failing must not fail the write that produced
        the event: the event is durable either way and the phone's cursor recovers
        it on the next subscription.
        """
        for sink in list(self._event_sinks):
            try:
                sink(account_id, event)
            except Exception as exc:  # noqa: BLE001 - delivery is best effort
                logger.warning("[open_android] Event sink failed: %s", exc)

    deliverEvent = deliver_event

    def account_exists(self, account_id: str) -> bool:
        """Whether this account was registered on this host.

        Login must never be the act that creates an account: an unknown
        username is an authentication failure, not a signup.
        """
        try:
            paths = account_paths(self.storage_root, account_id)
        except (ValueError, TypeError):
            return False
        return paths.database.is_file()

    has_gateway_account = account_exists

    def is_event_session_active(self, context: VerifiedRequestContext, now: datetime | str | None = None) -> bool:
        """Recheck lifecycle facts without replaying the signed handshake nonce."""
        try:
            paths = account_paths(self.storage_root, context.account_id)
            # A retained handle may reference a deleted/replaced account. Always
            # consult the current file without creating an unknown account.
            with closing(sqlite3.connect(paths.database.as_uri() + "?mode=ro", uri=True)) as database:
                row = database.execute(
                    "SELECT s.status, s.expires_at, k.pairing_generation "
                    "FROM access_sessions s JOIN device_keys k ON k.device_id = s.device_id "
                    "WHERE s.session_id = ? AND s.device_id = ?",
                    (context.session_id, context.device_id),
                ).fetchone()
                return bool(row and row[0] == "active" and _now(row[1]) > _now(now)
                            and int(row[2]) == context.pairing_generation)
        except (OSError, sqlite3.Error, AttributeError, TypeError, ValueError):
            return False

    def set_device_online(self, context: VerifiedRequestContext, online: bool) -> None:
        key = (context.account_id,context.device_id,context.session_id)
        with self._admission_lock:
            existing = self._online_devices.get(key)
            if online:
                if self.is_event_session_active(context):
                    self._online_devices[key] = (context,(existing[1] if existing else 0)+1)
            elif existing and existing[1] > 1:
                self._online_devices[key] = (existing[0],existing[1]-1)
            else:
                self._online_devices.pop(key,None)
        if not online and not self.is_device_online(context.account_id,context.device_id,context.pairing_generation) and self.account_exists(context.account_id):
            account=self.open_gateway_account(context.account_id)
            try:
                with account.store.transaction():
                    rows=account.store.database.execute("SELECT request_id FROM device_requests WHERE device_id=? AND pairing_generation=? AND risk='high-privilege-ephemeral' AND state='pending'",(context.device_id,context.pairing_generation)).fetchall()
                    for row in rows:
                        account.store.database.execute("UPDATE device_requests SET state='expired',parameters_json='',result_json='',expires_at=? WHERE request_id=?",(iso_millis(),row[0]))
                        account.events.release_device_request(row[0])
            finally:account.close()

    @contextmanager
    def _generation_cancel_lock(self, account_id: str, generation_id: str):
        key = (account_id, generation_id)
        with self._admission_lock:
            lock, users = self._cancel_locks.get(key, (threading.RLock(), 0))
            self._cancel_locks[key] = (lock, users + 1)
        try:
            with lock:
                yield
        finally:
            with self._admission_lock:
                _, users = self._cancel_locks[key]
                if users == 1:
                    del self._cancel_locks[key]
                else:
                    self._cancel_locks[key] = (lock, users - 1)

    def is_device_online(self, account_id: str, device_id: str, generation: int) -> bool:
        with self._admission_lock:
            contexts = [item[0] for key,item in self._online_devices.items() if key[:2] == (account_id,device_id)]
        return any(ctx.pairing_generation == generation and self.is_event_session_active(ctx) for ctx in contexts)

    def list_gateway_account_ids(self) -> list[str]:
        """List accounts that have persisted their opaque id for recovery scans."""
        account_ids: set[str] = set()
        if not self.storage_root.is_dir():
            return []
        for database_path in self.storage_root.glob("*/gateway.sqlite"):
            try:
                connection = sqlite3.connect(f"file:{database_path}?mode=ro", uri=True)
                try:
                    row = connection.execute(
                        "SELECT value FROM account_metadata WHERE key = 'gateway_account_id'"
                    ).fetchone()
                finally:
                    connection.close()
                if row is not None and isinstance(row[0], str):
                    account_ids.add(str(row[0]))
            except sqlite3.Error:
                logger.warning("[open_android] Unable to inspect account metadata at %s", database_path)
        return sorted(account_ids)

    listGatewayAccountIds = list_gateway_account_ids

    def command_catalog_response(self, language_code: str) -> dict[str, Any]:
        """The shared command catalog in one response.

        Each entry carries both spellings the two consumers read: the
        discovery fields (`invocation`, `title`, `acceptsArguments`) the phone
        renders, and the contract fields (`command`, `description`,
        `argumentHint`) the shared schema validates. Deriving one from the
        other here keeps a single source of truth.
        """
        catalog = tuple(self.command_catalog)
        fingerprint = hashlib.sha256(
            _json({"format": COMMAND_CATALOG_FORMAT, "commands": catalog}).encode("utf-8"),
        ).hexdigest()[:16]
        commands = []
        for entry in catalog:
            item = dict(entry)
            item.setdefault("command", item.get("invocation", ""))
            item.setdefault("argumentHint", item.get("title", "") if item.get("acceptsArguments") else "")
            commands.append(item)
        return {
            "format": COMMAND_CATALOG_FORMAT,
            "catalogVersion": f"cmdcat_{fingerprint}",
            "languageCode": language_code,
            "commands": commands,
        }

    @staticmethod
    def _coerce_aead(candidate: Any) -> tuple[str, Any] | None:
        provider = candidate
        reference: Any = None
        if isinstance(candidate, Mapping):
            provider = candidate.get("aead", candidate.get("cipher", candidate.get("provider")))
            reference = candidate.get("reference", candidate.get("keyReference"))
        if provider is None:
            return None
        if reference is None:
            reference = getattr(provider, "reference", getattr(provider, "key_reference", None))
        algorithm = getattr(provider, "algorithm", None)
        authenticated = getattr(provider, "authenticated", None)
        if (
            not isinstance(reference, str) or not reference
            or not isinstance(algorithm, str) or not algorithm
            or authenticated is not True
            or not callable(getattr(provider, "encrypt", None))
            or not callable(getattr(provider, "decrypt", None))
        ):
            return None
        return reference, provider

    def _resolve_key_binding(self, account_id: str) -> tuple[str, Any | None]:
        secret_store = self.secret_store
        if secret_store is None:
            return "", None
        name = f"open-android-intelligence-gateway/{account_id}"
        for method_name in ("get_or_create_aead", "get_aead", "get_or_create_secure_key"):
            method = getattr(secret_store, method_name, None)
            if callable(method):
                try:
                    binding = self._coerce_aead(method(name))
                except Exception:
                    return "", None
                return binding if binding is not None else ("", None)
        binding = self._coerce_aead(secret_store)
        if binding is not None:
            return binding
        for method_name in ("get_or_create", "get_or_create_secret", "reference_for"):
            method = getattr(secret_store, method_name, None)
            if not callable(method):
                continue
            try:
                candidate = method(name)
            except TypeError:
                try:
                    candidate = method(account_id)
                except Exception:
                    return "", None
            except Exception:
                return "", None
            binding = self._coerce_aead(candidate)
            return binding if binding is not None else ("", None)
        return "", None

    def _master_key_ref(self, paths: AccountPaths, account_id: str) -> str:
        del paths
        reference, _ = self._resolve_key_binding(account_id)
        return reference

    def open_gateway_account(self, account_id: str) -> GatewayAccount:
        # Resolve and validate the opaque account ID before constructing SQLite.
        paths = account_paths(self.storage_root, account_id)
        master_key_ref, aead = self._resolve_key_binding(account_id)
        store = AccountStore(
            paths, master_key_ref, self.commit_hook, aead,
            account_id=account_id, event_sink=self.deliver_event,
        )
        account = GatewayAccount(
            account_id, paths, store, self.contracts, self.attachment_policy,
            self.credential_verifier,
        )
        account.conversations.history_reader = self.history_reader
        return account

    def delete_gateway_account(self, account_id: str) -> bool:
        """Removes every artifact of one logical Gateway (contract section 13).

        The account directory *is* the logical Gateway: database, staged and
        confirmed attachment bytes, credentials and the account audit trail.
        Deletion is a resource-level transaction, so it never pretends to be
        per-attachment reducer events. The path comes from `account_paths`,
        the only place allowed to turn an opaque ID into a filesystem location.
        """
        paths = account_paths(self.storage_root, account_id)
        if not paths.root.is_dir():
            return False
        shutil.rmtree(paths.root)
        return True

    deleteGatewayAccount = delete_gateway_account

    def _negotiate(self, account: GatewayAccount, context: Mapping[str, Any], body: Any, now: datetime) -> Mapping[str, Any]:
        response = self._build_negotiation_response(body, account)
        if not self.contracts.validate("negotiate.response", response):
            raise GatewayError("INTERNAL_ERROR")
        account.store.database.execute(
            "INSERT OR REPLACE INTO negotiations(negotiation_id, response_json, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (body["negotiationId"], _json(response), iso_millis(now), iso_millis(now + timedelta(hours=24))),
        )
        return response

    def _build_negotiation_response(self, body: Any, account: GatewayAccount | None = None) -> Mapping[str, Any]:
        if not isinstance(body, Mapping) or not self.contracts.validate("negotiate.request", body):
            raise GatewayError("SCHEMA_INVALID")
        if body["schemaHashes"]["core"] != self.contracts.core_schema_hash:
            # Contract §4: a digest mismatch is a destructive upgrade, not a
            # transient failure — the client cannot connect at all until it is
            # rebuilt against these Schema documents. Without this line the
            # rejection is invisible to the operator (nothing is persisted yet).
            logger.warning(
                "[open_android] Refused negotiation: core Schema digest mismatch (%s)",
                _negotiation_client_hint(body, self.contracts.core_schema_hash),
            )
            raise GatewayError("PROTOCOL_INCOMPATIBLE")
        requested = body["features"]
        # Only what this Gateway implements is ever advertised: an
        # account-invitation or device-key flow this host cannot serve would be a
        # capability claim the phone would then rely on.
        supported_auth = {"password", "account-invitation", "refresh", "device-key"}
        auth = [item for item in requested["auth"] if item in supported_auth]
        # Only capabilities this adapter really serves. `agent-command-new-v1`
        # means the `/new` command entry exists here: it creates the new
        # conversation and answers with the authoritative id. Advertising it
        # without that entry would make the agreement a claim, not a fact.
        supported_conversation_ui = {"agent-command-catalog-v1", "agent-command-new-v1", "message-batches-v1", "newline-v1"}
        if self.generation_canceller is not None: supported_conversation_ui.add("generation-cancel-v1")
        if self.approval_cards_available:
            # Contract §7.2: only a Gateway that can actually release the blocked
            # Agent thread may promise the phone a card whose buttons do something.
            supported_conversation_ui = supported_conversation_ui | {APPROVAL_CAPABILITY}
        conversation_ui = [
            item for item in requested.get("conversationUi", [])
            if item in supported_conversation_ui
        ]
        required = {
            "messages": "chat-v1", "attachments": "staged-sha256-v1",
            "events": "sse-cursor-v1", "deviceRequests": "risk-queue-v1",
        }
        missing = [key for key in required if required[key] not in requested[key]]
        if missing:
            logger.warning(
                "[open_android] Refused negotiation: client does not offer %s (%s)",
                ", ".join(sorted(missing)),
                _negotiation_client_hint(body, self.contracts.core_schema_hash),
            )
            raise GatewayError("PROTOCOL_INCOMPATIBLE")
        identity = self.gateway_identity(account)
        features: dict[str, Any] = {"auth": auth, **required}
        if conversation_ui:
            features["conversationUi"] = conversation_ui
        return {
            "protocol": dict(PROTOCOL_VERSION),
            "features": features,
            "limits": {
                "attachmentTtlSeconds": self.attachment_policy.attachment_ttl_seconds,
                "eventRetentionSeconds": 86_400, "maxClockSkewSeconds": 120,
            },
            "gatewayIdentity": identity,
        }

    def gateway_identity(self, account: GatewayAccount | None = None) -> dict[str, Any]:
        if account is None:
            deployment_id = "deploy_" + hashlib.sha256(str(self.storage_root).encode("utf-8")).hexdigest()[:16]
            tls_identity = self.tls_spki_sha256
        else:
            metadata = {
                row["key"]: row["value"] for row in account.store.database.execute(
                    "SELECT key, value FROM account_metadata WHERE key IN ('deployment_id', 'tls_spki_sha256')"
                ).fetchall()
            }
            deployment_id = metadata.get("deployment_id", "deploy_hermes")
            rotated_pin = metadata.get("tls_spki_sha256")
            tls_identity = rotated_pin if isinstance(rotated_pin, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", rotated_pin) and rotated_pin != "sha256:" + "0" * 64 else self.tls_spki_sha256
        return {"deploymentId": deployment_id, "tlsSpkiSha256": tls_identity}

    def _pre_auth_context(self, request: Any, body: Mapping[str, Any]) -> dict[str, str]:
        return {
            "requestId": str(_value(request, "requestId", "request_id", default=body.get("negotiationId", "open-android-intelligence-negotiate"))),
            "correlationId": str(_value(request, "correlationId", "correlation_id", default=body.get("negotiationId", "open-android-intelligence-negotiate"))),
        }

    def _handle_pre_auth(self, request: Any) -> GatewayResponse:
        body = _request_body(request)
        context = self._pre_auth_context(request, body if isinstance(body, Mapping) else {})
        try:
            now = _request_now(request)
            self._admit_pre_auth(False, now)
            response = self._build_negotiation_response(body)
            negotiation_id = str(body["negotiationId"])
            now = _request_now(request)
            input_hash = _hash_input("POST", "/open-android-intelligence/v2/negotiate", body)
            with self._admission_lock:
                for key in list(self._pending_negotiations):
                    if self._pending_negotiations[key]["expiresAt"] <= now:
                        del self._pending_negotiations[key]
                existing = self._pending_negotiations.get(negotiation_id)
                if existing is not None:
                    if existing["inputHash"] != input_hash:
                        logger.warning(
                            "[open_android] Refused negotiation: %s was already started with a different body (%s)",
                            negotiation_id,
                            _negotiation_client_hint(body, self.contracts.core_schema_hash),
                        )
                        raise GatewayError("PROTOCOL_INCOMPATIBLE")
                else:
                    if len(self._pending_negotiations) >= 1000:
                        raise GatewayError("RATE_LIMITED")
                    self._pending_negotiations[negotiation_id] = {
                        "inputHash": input_hash,
                        "installationId": body["client"]["installationId"],
                        "response": dict(response),
                        "expiresAt": _now(now) + timedelta(minutes=5),
                        "accountId": None,
                    }
            return _success(context, response)
        except GatewayError as exc:
            code = "SCHEMA_INVALID" if exc.code == "INVALID_STATE_TRANSITION" else exc.code
            return _failure(context, code, exc.details)

    def _admit_pre_auth(self, password: bool, now: datetime) -> None:
        with self._admission_lock:
            if self._admission_window is None or now < self._admission_window or now >= self._admission_window + timedelta(minutes=1):
                self._admission_window = now
                self._negotiation_count = 0
            if password:
                if self._password_jobs >= 2:
                    raise GatewayError("RATE_LIMITED")
                self._password_jobs += 1
            else:
                self._negotiation_count += 1
                if self._negotiation_count > 1000:
                    raise GatewayError("RATE_LIMITED")

    def _admit_password(self, request: Any, account_id: str, now: datetime) -> None:
        with self._admission_lock:
            if self._password_jobs >= 2:
                raise GatewayError("RATE_LIMITED")
            for key, (window, _) in list(self._password_attempts.items()):
                if now < window or now >= window + timedelta(minutes=1):
                    del self._password_attempts[key]
            peer = _value(request, "remoteAddress", "remote_address")
            key = (peer if isinstance(peer, str) and peer else "internal", account_id)
            window, count = self._password_attempts.get(key, (now, 0))
            if count >= 30:
                raise GatewayError("RATE_LIMITED")
            # Bounded best-effort per-peer throttling, not a shared lockout.
            # Expensive work always remains bounded by the two global slots.
            self._password_attempts.pop(key, None)
            if len(self._password_attempts) >= 1000:
                del self._password_attempts[next(iter(self._password_attempts))]
            self._password_attempts[key] = (window, count + 1)
            self._password_jobs += 1

    def _handle_pairing_invite(self,request: Any) -> GatewayResponse:
        from .pairing_invites import PairingInvites
        body=_request_body(request); context=self._pre_auth_context(request,body if isinstance(body,Mapping) else {}); admitted=False
        try:
            now=_request_now(request); challenge=_value(request,"target").endswith("challenge")
            device='/sessions/device' in _value(request,'target')
            expected={"accountId","negotiationId","installationId","deviceId"} if device else {"accountId","negotiationId","code","installation"} if challenge else {"accountId","negotiationId","challengeId","signature"}
            if not isinstance(body,Mapping): raise GatewayError("SCHEMA_INVALID")
            if device and not challenge:
                if not self.contracts.validate('session.device',body): raise GatewayError('SCHEMA_INVALID')
            elif set(body)!=expected: raise GatewayError('SCHEMA_INVALID')
            for field in ('negotiationId', 'installationId', 'deviceId', 'challengeId'):
                if field in body and (not isinstance(body[field],str) or not re.fullmatch(r'[A-Za-z0-9._~-]{1,128}',body[field])):
                    raise GatewayError('SCHEMA_INVALID')
            account_id=body.get('accountId',body.get('username'))
            if not isinstance(account_id,str) or not self.account_exists(account_id) or not isinstance(body.get('negotiationId'),str): raise GatewayError('AUTHENTICATION_FAILED')
            installation=body.get("installation")
            if device:
                self.bind_negotiation(body['negotiationId'],account_id,body['installationId'],now)
            elif challenge:
                if not isinstance(installation,Mapping) or set(installation)!={"installationId","displayName","devicePublicKey"}: raise GatewayError("SCHEMA_INVALID")
                self.bind_negotiation(body["negotiationId"],account_id,installation["installationId"],now)
            else:
                pending=self._pending_negotiations.get(body["negotiationId"])
                if not pending or pending["expiresAt"]<=now: raise GatewayError("PROTOCOL_INCOMPATIBLE")
            self._admit_password(request,account_id,now); admitted=True
            account=self.open_gateway_account(account_id)
            try:
                service=PairingInvites(account)
                if device:
                    result=service.device_challenge(body['negotiationId'],body['installationId'],body['deviceId'],now) if challenge else service.device_exchange(body,context['correlationId'],now)
                    return _success(context,{**result,'accountId':account_id})
                if challenge: return _success(context,service.challenge(body["code"],body["negotiationId"],installation,now))
                return _success(context,{**service.exchange(body["challengeId"],body["signature"],body["negotiationId"],context["correlationId"],now),"accountId":account_id})
            finally: account.close()
        except GatewayError as exc: return _failure(context,exc.code,exc.details)
        finally:
            if admitted:
                with self._admission_lock: self._password_jobs-=1

    def _handle_session_password(self, request: Any) -> GatewayResponse:
        body = _request_body(request)
        context = self._pre_auth_context(request, body if isinstance(body, Mapping) else {})
        admitted = False
        try:
            now = _request_now(request)
            if not isinstance(body, Mapping) or not self.contracts.validate("session.password", body):
                raise GatewayError("SCHEMA_INVALID")
            installation = body["installation"]
            if not canonical_device_key(installation["devicePublicKey"]):
                raise GatewayError("SCHEMA_INVALID")
            account_id = body["username"]
            if not self.account_exists(account_id):
                raise GatewayError("AUTHENTICATION_FAILED")
            self.bind_negotiation(body["negotiationId"], account_id, installation["installationId"], now)
            self._admit_password(request, account_id, now)
            admitted = True
            account = self.open_gateway_account(account_id)
            try:
                bundle = account.sessions.create_password_session(account_id, body["password"], installation, context["correlationId"], now)
                return _success(context, {**bundle, "accountId": account_id})
            finally:
                account.close()
        except GatewayError as exc:
            return _failure(context, exc.code, exc.details)
        finally:
            if admitted:
                with self._admission_lock:
                    self._password_jobs -= 1

    def _handle_session_refresh(self, request: Any) -> GatewayResponse:
        """Rotates an access session from a refresh credential (pre-auth).

        The refresh credential is the only proof presented, so every field the
        schema makes mandatory is required here too: a request that names an
        account, device or installation that does not match the stored
        credential is rejected before anything is rotated.
        """
        body = _request_body(request)
        body_map = body if isinstance(body, Mapping) else {}
        context = self._pre_auth_context(request, body_map)
        now = _request_now(request)
        try:
            if not isinstance(body, Mapping) or not self.contracts.validate("session.refresh", body):
                raise GatewayError("SCHEMA_INVALID")
            account_id = str(body["accountId"])
            if not self.account_exists(account_id):
                raise GatewayError("AUTHENTICATION_FAILED")
            self.bind_negotiation(str(body["negotiationId"]), account_id, str(body["installationId"]), now)
            account = self.open_gateway_account(account_id)
            try:
                bundle = account.sessions.refresh(
                    refresh_credential=str(body["refreshCredential"]),
                    installation_id=str(body["installationId"]),
                    device_id=str(body["deviceId"]),
                    correlation_id=context["correlationId"],
                    now=now,
                )
            finally:
                account.close()
            response = dict(bundle)
            response["accountId"] = account_id
            return _success(context, response)
        except GatewayError as exc:
            code = "SCHEMA_INVALID" if exc.code == "INVALID_STATE_TRANSITION" else exc.code
            return _failure(context, code, exc.details)

    def _handle_session_logout(self, request: Any) -> GatewayResponse:
        """Ends the access session named by the request's own identity headers."""
        context = self._pre_auth_context(request, {})
        now = _request_now(request)
        try:
            headers = _request_headers(request)
            account_id = headers.get("x-open-android-intelligence-account")
            device_id = headers.get("x-open-android-intelligence-device")
            session_id = headers.get("x-open-android-intelligence-session")
            access_token = _bearer_token(headers)
            if not account_id or not device_id or not session_id or not access_token:
                raise GatewayError("AUTHENTICATION_REQUIRED")
            if not self.account_exists(account_id):
                raise GatewayError("AUTHENTICATION_FAILED")
            revoke_refresh = _query_flag(_value(request, "target"), "revokeRefresh")
            account = self.open_gateway_account(account_id)
            try:
                if not account.sessions.verify_access_token(access_token, session_id, device_id, now):
                    raise GatewayError("AUTHENTICATION_FAILED")
                account.sessions.revoke_session(session_id, context["correlationId"], now)
                if revoke_refresh:
                    account.sessions.revoke_refresh_credentials(device_id, context["correlationId"], now)
            finally:
                account.close()
            return _success(context, {"sessionId": session_id, "refreshRevoked": revoke_refresh})
        except GatewayError as exc:
            code = "SCHEMA_INVALID" if exc.code == "INVALID_STATE_TRANSITION" else exc.code
            return _failure(context, code, exc.details)

    def _handle_unpair(
        self, account: GatewayAccount, context: Mapping[str, Any], now: datetime,
    ) -> GatewayResponse:
        """`DELETE /pairings/current`: destroy the calling device's pairing.

        Reached only through the authenticated branch of `handle`, so the nine
        headers of contract §6.1 and the `Idempotency-Key` of §6.5 were already
        enforced upstream. That is deliberate and is the strength split D1
        asks for: ending your own session is an exempt route, destroying a
        pairing is a fully signed one.

        The device is taken from the verified context and from nowhere else —
        the route has no path parameter, so a body or query cannot retarget it
        at another device.
        """
        result = account.revoke_pairing(context["deviceId"], context["correlationId"], now)
        if not self.contracts.validate("session.unpair", result):
            raise GatewayError("SCHEMA_INVALID")
        return _success(context, result)

    def bind_negotiation(
        self, negotiation_id: str, account_id: str, installation_id: str,
        now: datetime | str | None = None,
    ) -> None:
        current = _now(now)
        pending = self._pending_negotiations.get(negotiation_id)
        if (
            pending is None
            or pending["expiresAt"] <= current
            or pending["installationId"] != installation_id
            or (pending["accountId"] is not None and pending["accountId"] != account_id)
        ):
            raise GatewayError("PROTOCOL_INCOMPATIBLE")
        account = self.open_gateway_account(account_id)
        try:
            with account.store.transaction():
                account.store.database.execute(
                    "INSERT OR REPLACE INTO negotiation_bindings(negotiation_id, account_id, installation_id, bound_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                    (negotiation_id, account_id, installation_id, iso_millis(current), iso_millis(pending["expiresAt"])),
                )
            pending["accountId"] = account_id
        finally:
            account.close()

    def _assert_negotiation_bound(self, account: GatewayAccount, context: Mapping[str, Any], now: datetime) -> None:
        negotiation_id = context.get("negotiationId")
        if negotiation_id is None:
            return
        installation_id = context.get("installationId")
        if installation_id is None:
            # Every other refusal on this path names the client it refused; a
            # rejection that leaves no trace is the one an operator cannot act
            # on, because nothing about it is persisted either.
            logger.warning(
                "[open_android] Refused request: negotiation %s arrived without an installation identity",
                negotiation_id,
            )
            raise GatewayError("PROTOCOL_INCOMPATIBLE")
        row = account.store.database.execute(
            "SELECT account_id, installation_id, expires_at FROM negotiation_bindings WHERE negotiation_id = ?",
            (negotiation_id,),
        ).fetchone()
        if row is None or row["account_id"] != context["accountId"] or row["installation_id"] != installation_id or _now(row["expires_at"]) <= now:
            logger.warning(
                "[open_android] Refused request: negotiation %s is not usable by installation %s (%s)",
                negotiation_id,
                installation_id,
                _negotiation_binding_reason(row, context, installation_id),
            )
            raise GatewayError("PROTOCOL_INCOMPATIBLE")

    def _idempotent_replay(
        self,
        account: GatewayAccount,
        context: Mapping[str, Any],
        now: datetime,
        input_hash: str,
        replay_check: Any,
    ) -> dict[str, Any] | None:
        """The answer already on record for this request, when there is one.

        Read-only, so it can run before any write lock is taken: a request whose
        outcome is known is answered from the ledger without reaching anything
        that has a side effect. `_run_idempotent` also calls it inside the
        transaction, where it is the authoritative check.
        """
        database = account.store.database
        uncertain = database.execute(
            "SELECT 1 FROM uncertain_outcomes WHERE device_id = ? AND request_id = ?",
            (context["deviceId"], context["requestId"]),
        ).fetchone()
        if uncertain is not None:
            return _failure(context, "OUTCOME_UNKNOWN")
        existing = database.execute(
            "SELECT input_hash, outcome_json, expires_at FROM idempotency_ledger WHERE device_id = ? AND request_id = ?",
            (context["deviceId"], context["requestId"]),
        ).fetchone()
        if existing is None:
            return None
        if existing["input_hash"] != input_hash:
            return _failure(context, "IDEMPOTENCY_CONFLICT")
        if _now(existing["expires_at"]) <= now:
            return _failure(context, "OUTCOME_UNKNOWN")
        if replay_check is not None:
            replay_error = replay_check()
            if replay_error is not None:
                return _failure(context, replay_error)
        return GatewayResponse(account.store.open_json(
            existing["outcome_json"],
            f"idempotency:{context['deviceId']}:{context['requestId']}",
        ))

    def _run_idempotent(
        self,
        account: GatewayAccount,
        request: Any,
        context: Mapping[str, Any],
        work: Any,
        replay_check: Any = None,
        preflight: Any = None,
    ) -> dict[str, Any]:
        """Run one mutating request once, with its outcome recorded.

        `preflight` is work that must not run while this request holds the write
        lock. Releasing the Agent thread blocked on an approval is a call into
        another runtime: anything that runtime does back onto this database would
        wait for a lock this request is holding until that call returns, so the
        hand-off has to happen first and the settlement it belongs to still has to
        land afterwards, in one transaction.

        Everything else on this path is unchanged, and a caller that passes no
        `preflight` gets exactly the behaviour it had before.
        """
        method = _value(request, "method")
        if method == "GET":
            return work()
        request_id = context["requestId"]
        idempotency_key = _value(request, "idempotencyKey", "idempotency_key")
        if idempotency_key != request_id:
            return _failure(context, "IDEMPOTENCY_CONFLICT")
        now = _request_now(request)
        input_hash = _hash_input(method, _value(request, "target"), _request_body(request))
        if preflight is not None:
            # A replay is answered from what was recorded and nothing else: the
            # work below is what the hook exists for, so letting it run again
            # would hand the host a second copy of a decision it already took.
            replayed = self._idempotent_replay(account, context, now, input_hash, replay_check)
            if replayed is not None:
                return replayed
            # The hook releases the host thread before the settlement below is
            # written, so the two are only inseparable for as long as they cannot be
            # interleaved — and they cannot be: decisions are dispatched synchronously
            # on the host event loop (see `GatewayHttpRoute.handle`) and nothing under
            # `handle` awaits, so a second request for this idempotency key, and a
            # second decision for this approval under another key, both wait until
            # this one has settled it. An embedding that lets two threads call
            # `handle` for one approval at once would have to gate this hook and the
            # settlement it belongs to together.
            preflight()
        with account.store.transaction(unknown_marker={
            "deviceId": context["deviceId"],
            "requestId": request_id,
            "inputHash": input_hash,
            "createdAt": iso_millis(now),
            "expiresAt": iso_millis(now + timedelta(days=30)),
        }):
            replayed = self._idempotent_replay(account, context, now, input_hash, replay_check)
            if replayed is not None:
                return replayed
            try:
                response = work()
            except GatewayError as exc:
                if exc.code not in _PERSISTABLE_ERRORS:
                    raise
                response = _failure(context, exc.code, exc.details)
            try:
                account.store.database.execute(
                    "INSERT INTO idempotency_ledger(device_id, request_id, input_hash, outcome_json, expires_at) VALUES (?, ?, ?, ?, ?)",
                    (
                        context["deviceId"], request_id, input_hash,
                        account.store.seal_json(response, f"idempotency:{context['deviceId']}:{request_id}"),
                        iso_millis(now + timedelta(days=30)),
                    ),
                )
            except sqlite3.Error as exc:
                raise TransactionOutcomeUnknown({"reason": "idempotency outcome persistence unknown"}) from exc
            return response

    def _handle_new_conversation(
        self,
        account: Any,
        source_conversation_id: str,
        client_message_id: str,
        correlation_id: str,
        device_id: str,
        request_id: str,
        now: datetime | str | None = None,
    ) -> dict[str, Any]:
        """
        The `/new` command entry (contract §7.1, ADR 0043).

        The phone never mints a conversation id of its own: it sends `/new`
        into the thread it is leaving, and this entry answers with the id the
        Agent host really created. Message acceptance, conversation creation,
        the event and the audit are one transaction, so an interruption cannot
        leave a conversation that exists without the event that names it, or
        an event pointing at a conversation nobody stored.

        The command itself stays in the source thread — the phone keeps showing
        it there — and the new thread starts empty.
        """
        current = _now(now)
        with account.store.transaction():
            accepted = account.conversations.accept_message(
                source_conversation_id, client_message_id, NEW_CONVERSATION_COMMAND,
                [], device_id, request_id, correlation_id, current, dispatch_to_agent=False,
            )
            created = account.conversations.create(
                # Derived from the id the phone chose for the command itself, so
                # the same request cannot end up with two new threads: a replay
                # of this request is answered from the idempotency ledger before
                # this code runs again.
                client_conversation_id=f"{client_message_id}-new",
                title=None,
                correlation_id=correlation_id,
                now=current,
            )
            account.events.append(
                "conversation.command.result",
                correlation_id,
                {
                    "command": "new",
                    "commandId": "new",
                    "outcome": "created-conversation",
                    "sourceConversationId": source_conversation_id,
                    "sourceMessageId": accepted["messageId"],
                    "conversationId": created["conversationId"],
                },
                current,
            )
            # The binding the command entry owns: this request asked for a new
            # thread and this thread is what it got. `agentSessionId` stays NULL
            # here — only the host runtime can name the session it created, and
            # it fills that column in through this same row rather than through an
            # id invented by the protocol layer. The row exists from this
            # transaction on, so the conversation can never be routed to a session
            # nobody recorded.
            account.agent_sessions.record(
                created["conversationId"],
                AgentSessionBindings.CREATED_VIA_NEW_COMMAND,
                request_id,
                current,
            )
            account.audit.append(
                "conversation.command.new",
                {"accountId": account.account_id, "deviceId": device_id},
                {
                    "command": "new",
                    "requestId": request_id,
                    "sourceConversationId": source_conversation_id,
                    "sourceMessageId": accepted["messageId"],
                    "conversationId": created["conversationId"],
                },
                correlation_id,
                current,
            )
        return {"message": accepted}

    def request_command_approval(
        self,
        account: GatewayAccount,
        approval_id: str,
        conversation_id: str,
        command: str,
        reason: str,
        options: list[dict[str, Any]],
        timeout_seconds: int,
        *,
        session_key: str | None = None,
        host_request_id: str | None = None,
        severity: str | None = None,
        correlation_id: str = "",
        now: datetime | str | None = None,
    ) -> dict[str, Any]:
        """Publish one command-execution approval as a structured card (§7.2).

        Writing the approval and its event in one transaction is what makes the
        card real: the event is only delivered after `COMMIT`, so a phone that
        sees the card can always read back the approval it is deciding on.

        `session_key` and the host's `request_id` are persisted but never leave
        this process: the phone is given `approvalId` and nothing else.
        """
        current = _now(now)
        with account.store.transaction():
            approval = account.approvals.record(
                approval_id, conversation_id, command, reason, options, timeout_seconds,
                session_key=session_key, host_request_id=host_request_id, severity=severity,
                requested_at=current, now=current,
            )
            account.events.append(
                APPROVAL_EVENT_REQUESTED, correlation_id or approval_id, {
                    "approvalId": approval_id,
                    "conversationId": conversation_id,
                    "command": str(command or ""),
                    "reason": str(reason or ""),
                    **({"severity": severity} if severity else {}),
                    "options": [
                        {
                            "choice": str(option.get("choice", "")),
                            **({"label": str(option["label"])} if option.get("label") else {}),
                            **({"style": str(option["style"])} if option.get("style") else {}),
                        }
                        for option in options
                    ],
                    "timeoutSeconds": int(approval["timeoutSeconds"]),
                    "requestedAt": int(approval["requestedAt"]),
                    "expiresAt": int(approval["expiresAt"]),
                }, current,
            )
            account.audit.append(
                "conversation.approval.requested",
                {"accountId": account.account_id, "conversationId": conversation_id},
                {"approvalId": approval_id, "timeoutSeconds": int(approval["timeoutSeconds"])},
                correlation_id or approval_id, current,
            )
        return account.approvals.lookup(approval_id) or approval

    def _settle_expired_approvals(self, account: GatewayAccount, now: datetime | str | None = None) -> int:
        """Turn every unanswered approval past its window into `timeout`.

        The Gateway — not the phone's countdown — decides that an approval is
        over, and it has to say so: contract §7.2 makes `timeout` the outcome the
        phone may trust, and a card left pending forever would tell the user a
        command is still waiting when nothing is.
        """
        current = _now(now)
        expired = account.approvals.pending_expired(current)
        if not expired:
            return 0
        settled = 0
        with account.store.transaction():
            for approval in expired:
                if not account.approvals.settle(approval["approvalId"], "timeout", now=current):
                    continue
                account.events.append(
                    APPROVAL_EVENT_RESOLVED, approval["approvalId"], {
                        "approvalId": approval["approvalId"],
                        "conversationId": approval["conversationId"],
                        "decision": "timeout",
                        # The window's own end, not the moment someone happened
                        # to look: a lazy sweep must not date the timeout to
                        # whenever the phone reconnected.
                        "decidedAt": int(approval.get("expiresAt") or 0),
                    }, current,
                )
                account.audit.append(
                    "conversation.approval.timeout",
                    {"accountId": account.account_id, "conversationId": approval["conversationId"]},
                    {"approvalId": approval["approvalId"], "decision": "timeout"},
                    approval["approvalId"], current,
                )
                settled += 1
        return settled

    def _prepare_approval_decision(
        self,
        account: GatewayAccount,
        approval_id: str,
        body: Any,
        now: datetime,
    ) -> dict[str, Any]:
        """Everything one decision needs before the Gateway writes anything.

        Deliberately read-only apart from the hand-off itself: this runs with no
        write lock held, so releasing the Agent thread blocked on the approval
        cannot leave another writer — the host runtime included — waiting on a
        lock this request owns until that call returns.

        A refusal is *returned* rather than raised. It still has to be recorded and
        answered from inside the request's transaction, so the closure that owns
        the transaction raises it: the code is persisted with the request, and the
        sweep a closed window needs is written in that same transaction rather than
        before it.
        """
        if not self.approval_cards_available:
            # Contract §7.2: a Gateway that never advertised the capability must
            # not accept this endpoint either. `APPROVAL_UNSUPPORTED` is absent
            # from the HTTP status table, so it answers 400 — the status the phone
            # already reads as "this Gateway cannot take a decision".
            return {"error": GatewayError("APPROVAL_UNSUPPORTED", {"approvalId": approval_id})}
        body_map = body if isinstance(body, Mapping) else None
        decision = body_map.get("decision") if body_map is not None else None
        if not isinstance(decision, str) or decision not in APPROVAL_CHOICES:
            return {"error": GatewayError("APPROVAL_DECISION_INVALID", {"approvalId": approval_id})}
        approval = account.approvals.lookup(approval_id)
        if approval is None:
            return {"error": GatewayError("APPROVAL_NOT_FOUND", {"approvalId": approval_id})}
        settled = approval.get("decision")
        if settled is not None:
            # The same decision replayed is the retry it looks like; a different
            # one is a second opinion on a question that is already answered.
            if settled == decision:
                return {"replayed": approval}
            return {"error": GatewayError(
                "APPROVAL_ALREADY_RESOLVED", {"approvalId": approval_id, "decision": settled},
            )}
        if int(approval.get("expiresAt") or 0) <= _epoch_millis(now):
            # Settling the closed window is a write, so it belongs to the
            # transaction below; only the answer it publishes is decided here.
            return {
                "error": GatewayError(
                    "APPROVAL_EXPIRED", {"approvalId": approval_id, "decision": "timeout"},
                ),
                "sweep": True,
            }
        return {
            "approval": approval,
            "decision": decision,
            "resolved": self._resolve_host_approval(
                str(approval.get("sessionKey") or ""), decision, approval.get("hostRequestId"),
            ),
        }

    def _already_settled_response(
        self,
        account: GatewayAccount,
        context: Mapping[str, Any],
        approval_id: str,
        decision: str,
    ) -> GatewayResponse:
        """The answer when this request did not win the write.

        The record is the authority: a settlement this request did not make is
        either the same decision arriving twice — the success it looks like — or a
        different one, which is a conflict rather than an update. Publishing the
        event regardless would tell the phone about a decision the database does
        not hold.
        """
        terminal = account.approvals.lookup(approval_id) or {}
        recorded = terminal.get("decision")
        if recorded == decision:
            return _success(context, {"approval": _public_approval(terminal)})
        raise GatewayError(
            "APPROVAL_ALREADY_RESOLVED", {"approvalId": approval_id, "decision": recorded},
        )

    def _handle_approval_decision(
        self, account: GatewayAccount, context: Mapping[str, Any], approval_id: str,
        body: Any, now: datetime, prepared: Mapping[str, Any] | None = None,
    ) -> GatewayResponse:
        """One button press: release the Agent thread and publish the outcome.

        `prepared` is what `_prepare_approval_decision` found with no write lock
        held. The fallback keeps this method usable on its own; every request path
        goes through the prepared one.
        """
        if prepared is None:
            prepared = self._prepare_approval_decision(account, approval_id, body, now)
        if prepared.get("sweep"):
            self._settle_expired_approvals(account, now)
        error = prepared.get("error")
        if error is not None:
            raise error
        replayed = prepared.get("replayed")
        if replayed is not None:
            return _success(context, {"approval": _public_approval(replayed)})
        approval = prepared.get("approval") or {}
        decision = str(prepared.get("decision") or "")
        if not prepared.get("resolved"):
            # The Agent is no longer waiting for this approval, so no decision
            # can release it. Recording the press as `allowed` would claim a
            # command ran that nobody is going to run. The settlement and its
            # event share one transaction, so no interruption can leave the
            # approval terminal without the event that says why.
            with account.store.transaction():
                withdrawn = account.approvals.settle(approval_id, "withdrawn", now=now)
                if withdrawn:
                    account.events.append(
                        APPROVAL_EVENT_RESOLVED, context["correlationId"], {
                            "approvalId": approval_id,
                            "conversationId": approval.get("conversationId"),
                            "decision": "withdrawn",
                            "decidedAt": _epoch_millis(now),
                        }, now,
                    )
            if not withdrawn:
                return self._already_settled_response(account, context, approval_id, decision)
            raise GatewayError("APPROVAL_EXPIRED", {"approvalId": approval_id, "decision": "withdrawn"})
        with account.store.transaction():
            # The atomic update decides whether there is an outcome to publish:
            # a settlement somebody else made is theirs, and an event claiming
            # this press won it would contradict the row it just failed to write.
            recorded = account.approvals.settle(
                approval_id, decision, device_id=context["deviceId"], now=now,
            )
            if recorded:
                account.events.append(
                    APPROVAL_EVENT_RESOLVED, context["correlationId"], {
                        "approvalId": approval_id,
                        "conversationId": approval.get("conversationId"),
                        "decision": decision,
                        "decidedAt": _epoch_millis(now),
                    }, now,
                )
                account.audit.append(
                    "conversation.approval.decision",
                    {"accountId": account.account_id, "deviceId": context["deviceId"]},
                    {"approvalId": approval_id, "decision": decision, "requestId": context["requestId"]},
                    context["correlationId"], now,
                )
        if not recorded:
            return self._already_settled_response(account, context, approval_id, decision)
        return _success(context, {
            "approval": _public_approval(account.approvals.lookup(approval_id) or approval),
        })

    def handle(self, request: VerifiedGatewayRequest) -> GatewayResponse:
        try:
            method = _value(request, "method")
            target = _value(request, "target")
            if _value(request, "context") is None:
                if method == "POST" and target == "/open-android-intelligence/v2/negotiate":
                    return self._handle_pre_auth(request)
                if method == "POST" and target in {"/open-android-intelligence/v2/sessions/invite/challenge","/open-android-intelligence/v2/sessions/invite/exchange","/open-android-intelligence/v2/pairings/exchange","/open-android-intelligence/v2/sessions/device/challenge","/open-android-intelligence/v2/sessions/device"}:
                    return self._handle_pairing_invite(request)
                if method == "POST" and target == "/open-android-intelligence/v2/sessions/password":
                    return self._handle_session_password(request)
                if method == "POST" and target == "/open-android-intelligence/v2/sessions/refresh":
                    return self._handle_session_refresh(request)
                if method == "DELETE" and isinstance(target, str) and (
                    target == "/open-android-intelligence/v2/sessions/current"
                    or target.startswith("/open-android-intelligence/v2/sessions/current?")
                ):
                    return self._handle_session_logout(request)
            if not isinstance(request, VerifiedGatewayRequest):
                raise GatewayError("AUTHENTICATION_REQUIRED")
            context = _request_context(request)
            account = self.open_gateway_account(context["accountId"])
            try:
                account.store.require_aead()
                self._assert_negotiation_bound(account, context, _request_now(request))
                body = _request_body(request)
                if _contains_identity_override(body):
                    return _failure(context, "IDENTITY_OVERRIDE_REJECTED")
                if method == "GET" and isinstance(target, str) and target.startswith("/open-android-intelligence/v2/events"):
                    # The window closes on the Gateway's clock, not on a device
                    # that happens to be connected: sweeping here is what turns an
                    # unanswered approval into the authoritative `timeout` the
                    # contract promises, even when nobody ever reconnects.
                    self._settle_expired_approvals(account, _request_now(request))
                    query = urlsplit(target).query
                    cursor = None
                    for part in query.split("&") if query else []:
                        if part.startswith("cursor="):
                            cursor = part[7:]
                    last_event_id = _value(request, "lastEventId", "last_event_id")
                    if last_event_id is not None and last_event_id != cursor:
                        return _failure(context, "CURSOR_CONFLICT")
                    try:
                        return _success(context, {"events": account.events.read_after(cursor, _request_now(request))})
                    except GatewayError as exc:
                        if exc.code == "CURSOR_EXPIRED":
                            return _failure(context, "CURSOR_EXPIRED", {"recoverableResources": ["conversations", "attachments", "device-requests"]})
                        raise

                parsed_target = urlsplit(str(target))
                target_path = parsed_target.path
                query_params: dict[str, str] = {}
                query_params = {key: values[0] for key, values in parse_qs(parsed_target.query).items() if len(values) == 1}

                # Filled by the decision preflight below and read by `work`'s
                # approval branch: the hand-off to the host has to happen with no
                # write lock held, while the settlement it belongs to still lands
                # inside this request's transaction.
                approval_handoff: dict[str, Any] = {}
                cancel_handoff: dict[str, Any] = {}
                now = _request_now(request)
                cancel_route = re.fullmatch(r"/open-android-intelligence/v2/conversations/([^/]+)/generations/([^/]+)/cancel",target_path) if method == "POST" else None

                def work() -> dict[str, Any]:
                    if cancel_route:
                        return _success(context,account.conversations.workflow.finish_cancel(*cancel_route.groups(),cancel_handoff["outcome"],context,now))
                    batch_route = re.fullmatch(r"/open-android-intelligence/v2/conversations/([^/]+)/message-batches",target_path) if method == "POST" else None
                    if batch_route:
                        return _success(context,account.conversations.workflow.accept_batch(batch_route.group(1),body,context,now))
                    media_match=re.fullmatch(r"/open-android-intelligence/v2/conversations/([^/]+)/attachments/([^/]+)/(metadata|cache-grant|content)",target_path)
                    if media_match:
                        from .history_media import HistoryMedia
                        conversation_id,media_id,operation=media_match.groups(); media=HistoryMedia(account)
                        if method=="GET" and operation=="metadata": return _success(context,{"metadata":media.metadata(conversation_id,media_id)})
                        if method=="POST" and operation=="cache-grant":
                            if body!={}: raise GatewayError("SCHEMA_INVALID")
                            return _success(context,media.grant(conversation_id,media_id,context,now))
                        if method=="GET" and operation=="content":
                            content,media_type=media.content(conversation_id,media_id,parse_qs(urlsplit(target).query).get("grantId",[""])[0],context,now)
                            return _success(context,{"contentBase64":base64.b64encode(content).decode(),"mediaType":media_type})
                        raise GatewayError("SCHEMA_INVALID")
                    if method == "GET" and target_path == "/open-android-intelligence/v2/sync/snapshot":
                        baseline = account.events.append("gateway.notice",context["correlationId"],{"noticeCode":"SYNC_BASELINE"},now=now)
                        pending = account.store.database.execute("SELECT request_id FROM device_requests WHERE device_id=? AND pairing_generation=? AND state IN ('pending','claimed','cancel_requested') ORDER BY created_at",(context["deviceId"],context["pairingGeneration"])).fetchall()
                        return _success(context,{"baselineCursor":baseline["eventId"],"conversations":account.conversations.list(),"pendingDeviceRequests":[r[0] for r in pending],"pairingGeneration":context["pairingGeneration"],"grantRevision":context["grantRevision"]})
                    if method == "GET" and target_path == "/open-android-intelligence/v2/pairings/current":
                        saved = account.store.database.execute("SELECT value FROM account_metadata WHERE key=?", (f"device-grant-digest:{context['deviceId']}",)).fetchone()
                        return _success(context,{"deviceId":context["deviceId"],"pairingGeneration":context["pairingGeneration"],"grantRevision":context["grantRevision"],**({"grantDigest":saved[0]} if saved else {})})
                    if method == "POST" and target_path == "/open-android-intelligence/v2/pairings/current/capabilities":
                        if (not isinstance(body, Mapping) or set(body) != {"bindings","expectedGrantRevision","localGrantRevision"}
                            or body["expectedGrantRevision"] != context["grantRevision"] or not isinstance(body["localGrantRevision"], int)):
                            raise GatewayError("GRANT_STALE")
                        account.device_requests.capabilities.validate_publication(body["bindings"])
                        digest = "sha256:" + hashlib.sha256(_jcs({"bindings":body["bindings"],"localGrantRevision":body["localGrantRevision"]}).encode()).hexdigest()
                        key = f"device-grant-digest:{context['deviceId']}"
                        prior = account.store.database.execute("SELECT value FROM account_metadata WHERE key=?", (key,)).fetchone()
                        revision = int(context["grantRevision"]) if prior and prior[0] == digest else account.bump_grant_revision(context["deviceId"],context["correlationId"],_request_now(request),grant_digest=digest)["grantRevision"]
                        account.device_requests.capabilities.register(context["deviceId"],int(context["pairingGeneration"]),revision,body["bindings"])
                        account.store.database.execute("INSERT OR REPLACE INTO account_metadata(key,value) VALUES (?,?)", (key,digest))
                        return _success(context,{"grantRevision":revision,"grantDigest":digest})
                    device_get = re.fullmatch(r"/open-android-intelligence/v2/device-requests/([^/]+)",target_path)
                    if method == "GET" and device_get:
                        record = account.device_requests.get(device_get.group(1))
                        if record["deviceId"] != context["deviceId"] or record["pairingGeneration"] != int(context["pairingGeneration"]):
                            raise GatewayError("PAIRING_GENERATION_STALE")
                        if record["grantRevision"] != int(context["grantRevision"]):
                            raise GatewayError("GRANT_STALE")
                        return _success(context,{"request":record})
                    if method == "DELETE" and target_path == "/open-android-intelligence/v2/pairings/current":
                        return self._handle_unpair(account, context, _request_now(request))
                    if method == "GET" and target_path == "/open-android-intelligence/v2/commands":
                        language_code = query_params.get("languageCode") or "en"
                        return _success(context, self.command_catalog_response(language_code))
                    current_generation=re.fullmatch(r"/open-android-intelligence/v2/conversations/([^/]+)/generations/current",target_path)
                    if method=='GET' and current_generation:
                        return _success(context,{'generation':account.conversations.workflow.current(current_generation.group(1))})
                    if method == "POST" and target_path == "/open-android-intelligence/v2/negotiate":
                        return _success(context, self._negotiate(account, context, body, _request_now(request)))
                    if method == "POST" and target_path == "/open-android-intelligence/v2/conversations":
                        body_map = body if isinstance(body, Mapping) else None
                        if body_map is None or not self.contracts.validate("conversation.create", body_map):
                            raise GatewayError("SCHEMA_INVALID")
                        return _success(context, {"conversation": account.conversations.create(
                            str(body_map["clientConversationId"]),
                            body_map.get("title"), context["correlationId"], _request_now(request),
                        )})
                    if method == "GET" and target_path == "/open-android-intelligence/v2/conversations":
                        return _success(context, {"conversations": account.conversations.list()})
                    message_match = re.fullmatch(r"/open-android-intelligence/v2/conversations/([^/]+)/messages", target_path)
                    if method == "GET" and message_match:
                        conv_id = message_match.group(1)
                        client_msg_id = query_params.get("clientMessageId")
                        cursor = query_params.get("cursor")
                        limit = int(query_params.get("limit", 50))
                        return _success(context, account.conversations.list_messages(
                            conv_id, client_message_id=client_msg_id, cursor=cursor, limit=limit,
                        ))
                    if method == "POST" and message_match:
                        body_map = body if isinstance(body, Mapping) else None
                        if body_map is None or not self.contracts.validate("message.create", body_map):
                            raise GatewayError("SCHEMA_INVALID")
                        attachments = body_map.get("attachments", [])
                        attachment_ids = [str(item["attachmentId"]) for item in attachments] if isinstance(attachments, list) else []
                        source_conversation_id = message_match.group(1)
                        client_message_id = str(body_map["clientMessageId"])
                        text_value = str(body_map["text"])
                        if text_value.strip() == NEW_CONVERSATION_COMMAND:
                            return _success(context, self._handle_new_conversation(
                                account,
                                source_conversation_id=source_conversation_id,
                                client_message_id=client_message_id,
                                correlation_id=context["correlationId"],
                                device_id=context["deviceId"],
                                request_id=context["requestId"],
                                now=_request_now(request),
                            ))
                        return _success(context, {"message": account.conversations.accept_message(
                            source_conversation_id, client_message_id, text_value,
                            attachment_ids, context["deviceId"], context["requestId"], context["correlationId"], _request_now(request),
                        )})
                    conversation_get = re.fullmatch(r"/open-android-intelligence/v2/conversations/([^/]+)", target_path)
                    if method == "GET" and conversation_get:
                        return _success(context, {"conversation": account.conversations.get(conversation_get.group(1))})
                    if method == "PATCH" and conversation_get:
                        body_map = None
                        if isinstance(body, (bytes, bytearray)):
                            try:
                                body_map = json.loads(body.decode("utf-8"))
                            except Exception:
                                pass
                        elif isinstance(body, str):
                            try:
                                body_map = json.loads(body)
                            except Exception:
                                pass
                        elif isinstance(body, Mapping):
                            body_map = body
                        if body_map is None:
                            raise GatewayError("SCHEMA_INVALID")
                        title = str(body_map.get("title", ""))
                        conv_id = conversation_get.group(1)
                        now = _request_now(request)
                        updated = account.conversations.update_title(
                            conv_id, title, context["correlationId"], now,
                        )
                        account.events.append(
                            "conversation.title.updated",
                            context["correlationId"],
                            {"conversationId": conv_id, "title": title, "newTitle": title},
                            now,
                        )
                        return _success(context, {"conversation": updated})
                    if method == "POST" and target_path == "/open-android-intelligence/v2/attachments":
                        body_map = body if isinstance(body, Mapping) else None
                        if body_map is None or not self.contracts.validate("attachment.create", body_map):
                            raise GatewayError("SCHEMA_INVALID")
                        return _success(context, {"attachment": account.attachments.create(
                            clientAttachmentId=str(body_map["clientAttachmentId"]),
                            filename=str(body_map["filename"]), mediaType=str(body_map["mediaType"]),
                            sizeBytes=int(body_map["sizeBytes"]), sha256=str(body_map["sha256"]),
                            deviceId=context["deviceId"], pairingGeneration=int(context["pairingGeneration"]),
                            correlationId=context["correlationId"], now=_request_now(request),
                        )})
                    attachment_content = re.fullmatch(r"/open-android-intelligence/v2/attachments/([^/]+)/content", target_path)
                    if method == "PUT" and attachment_content:
                        if isinstance(body, StreamedAttachmentUpload):
                            if body.attachment_id != attachment_content.group(1):
                                raise GatewayError("SCHEMA_INVALID")
                            return _success(context, {"attachment": account.attachments.accept_streamed_upload(
                                body, _request_now(request),
                            )})
                        if not isinstance(body, (bytes, bytearray, memoryview)):
                            raise GatewayError("SCHEMA_INVALID")
                        return _success(context, {"attachment": account.attachments.upload_content(
                            attachment_content.group(1), bytes(body), _request_now(request),
                        )})
                    attachment_commit = re.fullmatch(r"/open-android-intelligence/v2/attachments/([^/]+)/commit", target_path)
                    if method == "POST" and attachment_commit:
                        return _success(context, {"attachment": account.attachments.commit(
                            attachment_commit.group(1), _request_now(request),
                        )})
                    attachment_get = re.fullmatch(r"/open-android-intelligence/v2/attachments/([^/]+)", target_path)
                    if method == "GET" and attachment_get:
                        attachment = account.attachments.get(
                            attachment_get.group(1), _request_now(request),
                        )
                        return _success(context, {"attachment": {
                            key: attachment[key]
                            for key in ("attachmentId", "status", "sizeBytes", "sha256")
                        }})
                    claim_match = re.fullmatch(r"/open-android-intelligence/v2/device-requests/([^/]+)/claim", target_path)
                    if method == "POST" and claim_match:
                        return _success(context, account.device_requests.claim(
                            request_id=claim_match.group(1), device_id=context["deviceId"],
                            pairing_generation=int(context["pairingGeneration"]), grant_revision=int(context["grantRevision"]),
                            correlation_id=context["correlationId"], now=_request_now(request),
                        ))
                    result_match = re.fullmatch(r"/open-android-intelligence/v2/device-requests/([^/]+)/result", target_path)
                    if method == "POST" and result_match:
                        body_map = body if isinstance(body, Mapping) else None
                        if body_map is None or int(body_map.get("grantRevision", -1)) != int(context["grantRevision"]):
                            raise GatewayError("GRANT_STALE")
                        result_value = body_map.get("result")
                        if not isinstance(result_value, Mapping) or result_value.get("outcome") not in {"succeeded", "failed", "denied", "cancelled", "outcome_unknown"}:
                            raise GatewayError("SCHEMA_INVALID")
                        return _success(context, {"deviceRequest": account.device_requests.submit_result(
                            request_id=result_match.group(1), device_id=context["deviceId"],
                            pairing_generation=int(context["pairingGeneration"]), grant_revision=int(context["grantRevision"]),
                            claim_id=str(body_map.get("claimId")), result=result_value,
                            correlation_id=context["correlationId"], now=_request_now(request),
                        )})
                    device_get = re.fullmatch(r"/open-android-intelligence/v2/device-requests/([^/]+)", target_path)
                    if method == "GET" and device_get:
                        return _success(context, {"deviceRequest": account.device_requests.get(device_get.group(1))})
                    decision_match = re.fullmatch(r"/open-android-intelligence/v2/approvals/([^/]+)/decisions", target_path)
                    if method == "POST" and decision_match:
                        return self._handle_approval_decision(
                            account, context, decision_match.group(1), body, _request_now(request),
                            approval_handoff.get("prepared"),
                        )
                    return _failure(context, "SCHEMA_INVALID")

                replay_check = None
                claim_match = re.fullmatch(r"/open-android-intelligence/v2/device-requests/([^/]+)/claim", target_path)
                if method == "POST" and claim_match:
                    replay_check = lambda: account.device_requests.validate_claim_replay(
                        claim_match.group(1), context["deviceId"], int(context["pairingGeneration"]),
                        int(context["grantRevision"]), _request_now(request),
                    )
                result_match = re.fullmatch(r"/open-android-intelligence/v2/device-requests/([^/]+)/result", target_path)
                if method == "POST" and result_match and isinstance(body, Mapping):
                    replay_check = lambda: account.device_requests.validate_result_replay(
                        result_match.group(1), context["deviceId"], int(context["pairingGeneration"]),
                        int(context["grantRevision"]), str(body.get("claimId")), _request_now(request),
                    )
                decision_route = re.fullmatch(r"/open-android-intelligence/v2/approvals/([^/]+)/decisions", target_path)
                decision_preflight = None
                if method == "POST" and decision_route:
                    # Resolved outside the write transaction on purpose: the host
                    # hand-off below must not run while this request owns the
                    # database's write lock.
                    decision_approval_id = decision_route.group(1)
                    decision_now = _request_now(request)

                    def decision_preflight() -> None:
                        approval_handoff["prepared"] = self._prepare_approval_decision(
                            account, decision_approval_id, body, decision_now,
                        )

                if cancel_route:
                    if not isinstance(body,Mapping) or set(body)!={"requestId"} or body["requestId"] != context["requestId"]: raise GatewayError("SCHEMA_INVALID")
                    def decision_preflight() -> None:
                        native_cancel = (lambda cid,gid: self.generation_canceller(context["accountId"],cid,gid)) if self.generation_canceller else None
                        cancel_handoff["outcome"] = account.conversations.workflow.prepare_cancel(*cancel_route.groups(),context,native_cancel)
                if cancel_route:
                    with self._generation_cancel_lock(context['accountId'], cancel_route.group(2)):
                        return self._run_idempotent(account, request, context, work, replay_check, decision_preflight)
                return self._run_idempotent(account, request, context, work, replay_check, decision_preflight)
            finally:
                account.close()
        except GatewayError as exc:
            try:
                context = _request_context(request)
            except GatewayError:
                context = {"requestId": "open-android-intelligence-route", "correlationId": "open-android-intelligence-route"}
            code = "SCHEMA_INVALID" if exc.code == "INVALID_STATE_TRANSITION" else exc.code
            return _failure(context, code, exc.details)
        except Exception:
            try:
                context = _request_context(request)
            except GatewayError:
                context = {"requestId": "open-android-intelligence-route", "correlationId": "open-android-intelligence-route"}
            return _failure(context, "INTERNAL_ERROR")

    def run_shared_vectors(self, contract_root: str | Path | None = None) -> list[dict[str, Any]]:
        registry = ContractRegistry(contract_root or self.contract_root)
        fixtures = json.loads((registry.root / "vectors/dispatched-schema-fixtures.json").read_text())
        registry.dispatched_registry_id = fixtures["bindingSets"][0]["id"]
        registry._catalog = {registry._logical_key(item["key"]): {"schema":item["schema"],"schemaSha256":item["key"]["schemaSha256"]} for item in fixtures["catalogEntries"]}
        registry._bindings = {registry.dispatched_registry_id: {registry._logical_key(item["key"]): item["schemaSha256"] for item in fixtures["bindingSets"][0]["bindings"]}}

        vector_files = SHARED_VECTOR_FILE_NAMES
        results: list[dict[str, Any]] = []
        for file_name in vector_files:
            document = json.loads((registry.root / "vectors" / file_name).read_text(encoding="utf-8"))
            for case in document["cases"]:
                operation = case["operation"]
                input_value = case["input"]
                try:
                    if operation == "request.target":
                        actual_value = {"canonicalTarget": canonicalize_target(input_value["target"])}
                    elif operation == "request.signature":
                        actual_value = {"preimageHex": request_signature_preimage(input_value).hex()}
                    elif operation == "schema.validate":
                        if not registry.validate(input_value["schemaName"], input_value["value"]):
                            raise GatewayError("SCHEMA_INVALID")
                        actual_value = {"valid": True}
                    elif operation == "schema.validate_dispatched":
                        if not registry.validate_dispatched(input_value["fixtureBindingSetId"], input_value["dispatch"], input_value["value"]):
                            raise GatewayError("SCHEMA_INVALID")
                        actual_value = {"valid": True}
                    elif operation == "attachment.transition":
                        actual_value = {"nextState": next_attachment_state(input_value["current"], input_value["event"])}
                    elif operation == "device.transition":
                        actual_value = {"nextState": next_device_request_state(input_value["current"], input_value["event"])}
                    elif operation == "device.maximum_queue_seconds":
                        actual_value = {"seconds": maximum_device_request_queue_seconds(input_value["risk"])}
                    else:
                        raise GatewayError("SCHEMA_INVALID")
                    actual = {
                        "vectorId": case["id"], "operation": operation,
                        "outcome": "value", "value": actual_value,
                    }
                except GatewayError as exc:
                    actual = {
                        "vectorId": case["id"], "operation": operation,
                        "outcome": "error", "code": exc.code,
                    }
                expected = case["expected"]
                expected_projection = ({"outcome": "value", "value": expected["value"]}
                                       if expected["outcome"] == "value"
                                       else {"outcome": "error", "code": expected["code"]})
                actual_projection = {key: actual[key] for key in ("outcome", "value", "code") if key in actual}
                result = {
                    "vectorId": case["id"],
                    "operation": operation,
                    "implementation": "hermes-python",
                    "status": "pass" if actual_projection == expected_projection else "fail",
                    "resultHash": "sha256:" + hashlib.sha256(_jcs(actual).encode("utf-8")).hexdigest(),
                }
                results.append(result)
        return results

    openGatewayAccount = open_gateway_account


def create_gateway_core(storage_root: str | Path | None = None, **options: Any) -> GatewayCore:
    return GatewayCore(storage_root=storage_root, **options)


def open_gateway_account(account_id: str, storage_root: str | Path | None = None) -> GatewayAccount:
    return create_gateway_core(storage_root).open_gateway_account(account_id)


createGatewayCore = create_gateway_core
