"""Test-only secure storage provider doubles for Hermes Gateway tests."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Mapping
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from open_android_intelligence_gateway.core import VerifiedGatewayRequest, VerifiedRequestContext, _contract_root


class HermesAeadProviderDouble:
    """A deterministic test double for the host-provided AEAD boundary.

    Production code never uses this implementation.  It only provides an
    authenticated, non-plaintext round trip so tests can verify that the
    Gateway calls the host encryption interface and binds associated data.
    """

    algorithm = "test-aead"
    authenticated = True

    def __init__(self, reference: str, key: bytes):
        self.reference = reference
        self._key = key

    def _stream(self, nonce: bytes, length: int) -> bytes:
        blocks: list[bytes] = []
        total = 0
        counter = 0
        while total < length:
            block = hmac.new(self._key, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest()
            blocks.append(block)
            total += len(block)
            counter += 1
        return b"".join(blocks)[:length]

    def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
        nonce = secrets.token_bytes(12)
        ciphertext = bytes(value ^ mask for value, mask in zip(plaintext, self._stream(nonce, len(plaintext))))
        tag = hmac.new(self._key, associated_data + nonce + ciphertext, hashlib.sha256).digest()
        return b"test-aead-v1" + nonce + tag + ciphertext

    def decrypt(self, ciphertext: bytes, associated_data: bytes) -> bytes:
        prefix = b"test-aead-v1"
        if not ciphertext.startswith(prefix) or len(ciphertext) < len(prefix) + 12 + 32:
            raise ValueError("invalid test ciphertext")
        offset = len(prefix)
        nonce = ciphertext[offset:offset + 12]
        offset += 12
        tag = ciphertext[offset:offset + 32]
        encrypted = ciphertext[offset + 32:]
        expected = hmac.new(self._key, associated_data + nonce + encrypted, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise ValueError("test ciphertext authentication failed")
        return bytes(value ^ mask for value, mask in zip(encrypted, self._stream(nonce, len(encrypted))))


class HermesSecretStoreDouble:
    """Per-name stable key provider used only by tests."""

    def __init__(self):
        self._keys: dict[str, bytes] = {}

    def get_or_create_aead(self, name: str) -> HermesAeadProviderDouble:
        key = self._keys.setdefault(name, secrets.token_bytes(32))
        return HermesAeadProviderDouble(f"test-secret://{name}", key)


def make_secret_store() -> HermesSecretStoreDouble:
    return HermesSecretStoreDouble()


def seed_event_session(core, account_id="acct_alice", device_id="dev_1", session_id="sess_1"):
    """Lifecycle rows for transport tests whose handshake verifier is a double."""
    account = core.open_gateway_account(account_id)
    try:
        with account.store.transaction():
            account.store.database.execute(
                "INSERT OR IGNORE INTO device_keys(device_id, installation_id, public_key, pairing_generation, grant_revision, registered_at) VALUES (?, 'install_stream', ?, 1, 1, '2026-09-13T00:00:00.000Z')",
                (device_id, "A" * 43),
            )
            account.store.database.execute(
                "INSERT OR IGNORE INTO access_sessions(session_id, installation_id, device_id, status, created_at, expires_at) VALUES (?, 'install_stream', ?, 'active', '2026-09-13T00:00:00.000Z', '2999-01-01T00:00:00.000Z')",
                (session_id, device_id),
            )
    finally:
        account.close()


class IdentityProofVerifierDouble:
    """Test-only verifier for the structured identity continuity seam."""

    def verify(self, payload: bytes, signature: str, previous_identity_ref: str) -> bool:
        return bool(payload) and previous_identity_ref and signature == "valid-rotation-proof"


class PasswordVerifierDouble:
    """Test-only credential verifier; no password is persisted by the Gateway."""

    def verify(self, account_id, username, password, installation):
        return (
            bool(account_id)
            and username == "alice"
            and password in {"password", "backup password"}
            and isinstance(installation, Mapping)
            and bool(installation.get("installationId"))
            and bool(installation.get("devicePublicKey"))
        )


def core_schema_hash() -> str:
    """The real contract digest, so negotiation tests exercise the shipped check."""
    from open_android_intelligence_gateway.core import ContractRegistry

    return ContractRegistry().core_schema_hash


def make_verified_request(value: Mapping) -> VerifiedGatewayRequest:
    context = value["context"]
    if not isinstance(context, VerifiedRequestContext):
        context = VerifiedRequestContext(**dict(context))
    return VerifiedGatewayRequest(
        context=context,
        method=value["method"],
        target=value["target"],
        body=value.get("body"),
        idempotencyKey=value.get("idempotencyKey", value.get("idempotency_key")),
        lastEventId=value.get("lastEventId", value.get("last_event_id")),
        now=value.get("now"),
    )


def trust_core(core):
    """Model a host verifier converting its result to the typed Core seam."""

    original_handle = core.handle

    def handle(request):
        if isinstance(request, Mapping) and request.get("context") is not None:
            request = make_verified_request(request)
        return original_handle(request)

    core.handle = handle
    return core


def contract_root() -> Path:
    """The contract this session runs against.

    Resolved the same way production resolves it, rather than by counting
    parent directories: this package ships standalone, so where the contract
    lives depends on the pin or the operator override, not on the checkout
    layout. ``conftest`` has already guaranteed one is reachable.
    """
    return _contract_root()


def enqueue_fixture(account, *args, **kwargs):
    """Explicit device binding for old queue unit tests. Production has no fixture fallback."""
    import inspect, json
    supplied = dict(inspect.signature(account.device_requests.enqueue).bind_partial(*args, **kwargs).arguments)
    aliases = supplied.pop("aliases", {})
    supplied.update(aliases)
    def value(snake, camel): return supplied.get(snake, supplied.get(camel))
    entries = json.loads((contract_root()/"vectors/dispatched-schema-fixtures.json").read_text())["catalogEntries"]
    fixture = next(entry for entry in entries if entry["key"]["kind"] == "device.request")
    key = fixture["key"]
    binding = {name:key[name] for name in ("pluginId","authorKeyId","capabilityId","capabilityVersion","schemaSha256")}
    binding.update(schema=fixture["schema"],risk=value("risk","risk"))
    account.device_requests.capabilities.register(value("device_id","deviceId"),value("pairing_generation","pairingGeneration"),value("grant_revision","grantRevision"),[binding])
    return account.device_requests.enqueue(*args, **kwargs)
