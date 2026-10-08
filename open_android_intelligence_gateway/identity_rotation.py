"""Gateway identity rotation with durable continuity evidence."""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from .core import GatewayCore, GatewayError, _jcs, iso_millis


_TLS_SPKI_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class RotationProof:
    previous_identity_ref: str
    next_identity_ref: str
    next_tls_spki_sha256: str
    pairing_generation: int
    signature: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.previous_identity_ref, str) or not self.previous_identity_ref
            or not isinstance(self.next_identity_ref, str) or not self.next_identity_ref
            or not isinstance(self.next_tls_spki_sha256, str)
            or not _TLS_SPKI_PATTERN.fullmatch(self.next_tls_spki_sha256)
            or self.next_tls_spki_sha256 == "sha256:" + "0" * 64
            or not isinstance(self.pairing_generation, int)
            or isinstance(self.pairing_generation, bool) or self.pairing_generation < 0
            or not isinstance(self.signature, str) or not self.signature
        ):
            raise ValueError("invalid rotation proof")

    @classmethod
    def parse(cls, value: Any) -> "RotationProof":
        if isinstance(value, cls):
            return value
        if not isinstance(value, Mapping) or set(value) != {
            "previousIdentityRef", "nextIdentityRef", "nextTlsSpkiSha256",
            "pairingGeneration", "signature",
        }:
            raise GatewayError("IDENTITY_ROTATION_PROOF_INVALID")
        previous = value["previousIdentityRef"]
        next_identity = value["nextIdentityRef"]
        fingerprint = value["nextTlsSpkiSha256"]
        generation = value["pairingGeneration"]
        signature = value["signature"]
        if (
            not isinstance(previous, str) or not previous
            or not isinstance(next_identity, str) or not next_identity
            or not isinstance(fingerprint, str) or not _TLS_SPKI_PATTERN.fullmatch(fingerprint)
            or fingerprint == "sha256:" + "0" * 64
            or not isinstance(generation, int) or isinstance(generation, bool) or generation < 0
            or not isinstance(signature, str) or not signature
        ):
            raise GatewayError("IDENTITY_ROTATION_PROOF_INVALID")
        return cls(previous, next_identity, fingerprint, generation, signature)

    def payload(self, account_id: str) -> bytes:
        return _jcs({
            "accountId": account_id,
            "previousIdentityRef": self.previous_identity_ref,
            "nextIdentityRef": self.next_identity_ref,
            "nextTlsSpkiSha256": self.next_tls_spki_sha256,
            "pairingGeneration": self.pairing_generation,
        }).encode("utf-8")


class IdentityRotationService:
    def __init__(
        self, storage_root: str | Path | None = None, core: GatewayCore | None = None,
        proof_verifier: Any = None,
    ):
        self.core = core or GatewayCore(storage_root=storage_root)
        self.proof_verifier = proof_verifier

    def rotate(
        self, account_id: str, previous_identity_ref: str,
        next_identity_ref: str, signed_by_previous: Mapping[str, Any] | RotationProof,
        correlation_id: str, now: datetime | str | None = None,
    ) -> dict[str, Any]:
        proof = RotationProof.parse(signed_by_previous)
        if proof.previous_identity_ref != previous_identity_ref or proof.next_identity_ref != next_identity_ref:
            raise GatewayError("IDENTITY_ROTATION_PROOF_INVALID")
        if self.proof_verifier is None:
            raise GatewayError("IDENTITY_ROTATION_PROOF_UNVERIFIED")
        account = self.core.open_gateway_account(account_id)
        try:
            with account.store.transaction():
                current = account.store.database.execute(
                    "SELECT value FROM account_metadata WHERE key = 'gateway_identity_ref'"
                ).fetchone()[0]
                if current != previous_identity_ref:
                    raise GatewayError("TLS_IDENTITY_REQUIRED")
                generation = int(account.store.database.execute(
                    "SELECT value FROM account_metadata WHERE key = 'pairing_generation'"
                ).fetchone()[0])
                if proof.pairing_generation != generation:
                    raise GatewayError("IDENTITY_ROTATION_PROOF_INVALID")
                payload = proof.payload(account_id)
                verifier = getattr(self.proof_verifier, "verify", self.proof_verifier)
                try:
                    verified = verifier(payload, proof.signature, previous_identity_ref)
                except Exception as exc:
                    raise GatewayError("IDENTITY_ROTATION_PROOF_UNVERIFIED") from exc
                if verified is not True:
                    raise GatewayError("IDENTITY_ROTATION_PROOF_UNVERIFIED")
                receipt_id = f"rot_{uuid.uuid4()}"
                rotated_at = iso_millis(now)
                account.store.database.execute(
                    "INSERT INTO identity_rotation_receipts(receipt_id, previous_identity_ref, next_identity_ref, proof_hash, master_key_ref, rotated_at, correlation_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        receipt_id, previous_identity_ref, next_identity_ref,
                        hashlib.sha256(payload + b"\n" + proof.signature.encode("utf-8")).hexdigest(),
                        account.master_key_ref, rotated_at, correlation_id,
                    ),
                )
                account.store.database.execute(
                    "UPDATE account_metadata SET value = ? WHERE key = 'gateway_identity_ref'",
                    (next_identity_ref,),
                )
                generation = int(account.store.database.execute(
                    "SELECT value FROM account_metadata WHERE key = 'pairing_generation'"
                ).fetchone()[0])
                account.store.database.execute(
                    "UPDATE account_metadata SET value = ? WHERE key = 'pairing_generation'",
                    (str(generation + 1),),
                )
                account.store.database.execute(
                    "UPDATE account_metadata SET value = ? WHERE key = 'tls_spki_sha256'",
                    (proof.next_tls_spki_sha256,),
                )
                account.audit.append(
                    "gateway.identity.rotated", {"accountId": account_id},
                    {
                        "receiptId": receipt_id,
                        "previousIdentitySha256": hashlib.sha256(previous_identity_ref.encode("utf-8")).hexdigest(),
                        "nextIdentitySha256": hashlib.sha256(next_identity_ref.encode("utf-8")).hexdigest(),
                    }, correlation_id, rotated_at,
                )
                return {
                    "receiptId": receipt_id, "accountId": account_id,
                    "previousIdentityRef": previous_identity_ref, "nextIdentityRef": next_identity_ref,
                    "nextTlsSpkiSha256": proof.next_tls_spki_sha256,
                    "masterKeyRef": account.master_key_ref, "rotatedAt": rotated_at,
                }
        finally:
            account.close()


def rotate_identity(
    request: dict[str, Any], storage_root: str | Path | None = None,
    proof_verifier: Any = None,
) -> dict[str, Any]:
    return IdentityRotationService(storage_root=storage_root, proof_verifier=proof_verifier).rotate(
        request["accountId"], request["previousIdentityRef"], request["nextIdentityRef"],
        request["signedByPrevious"], request["correlationId"], request.get("now"),
    )
