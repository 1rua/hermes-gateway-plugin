from test_support import enqueue_fixture
import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from open_android_intelligence_gateway.backup import GatewayBackupService
from open_android_intelligence_gateway.core import GatewayError, create_gateway_core
from open_android_intelligence_gateway.identity_rotation import IdentityRotationService
from test_support import (
    IdentityProofVerifierDouble,
    PasswordVerifierDouble,
    core_schema_hash,
    make_secret_store,
    trust_core,
)


_real_create_gateway_core = create_gateway_core


def create_gateway_core(storage_root=None, **options):
    options.setdefault("secret_store", make_secret_store())
    options.setdefault("credential_verifier", PasswordVerifierDouble())
    return trust_core(_real_create_gateway_core(storage_root=storage_root, **options))


def _rotation_proof(
    previous_identity_ref="spki_initial", next_identity_ref="spki_new",
    next_tls_spki_sha256="sha256:" + "1" * 64, pairing_generation=1,
    signature="valid-rotation-proof",
):
    return {
        "previousIdentityRef": previous_identity_ref,
        "nextIdentityRef": next_identity_ref,
        "nextTlsSpkiSha256": next_tls_spki_sha256,
        "pairingGeneration": pairing_generation,
        "signature": signature,
    }


def test_portable_backup_excludes_active_identity_credentials_queue_and_content(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_alice")
    initial_master_key_ref = account.master_key_ref
    session = account.sessions.create_password_session(
        username="alice",
        password="backup password",
        installation={
            "installationId": "install_backup",
            "displayName": "Alice phone",
            "devicePublicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        },
        correlation_id="cor_login",
    )
    body = b"backup must not contain this staged body"
    attachment = account.attachments.create(
        client_attachment_id="att_backup",
        filename="backup.txt",
        media_type="text/plain",
        size_bytes=len(body),
        sha256=hashlib.sha256(body).hexdigest(),
        correlation_id="cor_attachment",
    )
    account.attachments.upload_content(attachment["attachmentId"], body)
    account.attachments.commit(attachment["attachmentId"])
    account.attachments.mark_delivered(attachment["attachmentId"])
    account.attachments.acknowledge(attachment["attachmentId"], "cor_ack")
    enqueue_fixture(account,
        request_id="device_req_pending_backup",
        device_id=session["deviceId"],
        pairing_generation=1,
        grant_revision=1,
        risk="read",
        capability={"id": "org.openandroidintelligence.sms.query", "version": "1.0.0"},
        provider={"pluginId": "org.openandroidintelligence.sms", "authorKeyId": "sha256:" + "a" * 64},
        parameters={"query": "from:alice"},
        correlation_id="cor_device",
        now="2026-08-27T00:00:00.000Z",
    )
    account.close()

    receipt = IdentityRotationService(
        core=core, proof_verifier=IdentityProofVerifierDouble()
    ).rotate(
        account_id="acct_alice",
        previous_identity_ref="spki_initial",
        next_identity_ref="spki_new",
        signed_by_previous=_rotation_proof(),
        correlation_id="cor_rotate",
    )
    assert receipt["accountId"] == "acct_alice"
    assert receipt["previousIdentityRef"] == "spki_initial"
    assert receipt["nextIdentityRef"] == "spki_new"
    assert receipt["nextTlsSpkiSha256"] == "sha256:" + "1" * 64
    assert receipt["masterKeyRef"] == initial_master_key_ref

    reopened = core.open_gateway_account("acct_alice")
    assert reopened.master_key_ref == initial_master_key_ref
    backup = GatewayBackupService(storage_root=tmp_path).export_portable("acct_alice")
    backup_json = json.dumps(backup, ensure_ascii=False)

    assert backup["accountId"] == "acct_alice"
    assert len(backup["masterKeyContinuitySha256"]) == 64
    assert "backup.txt" in backup_json
    assert "backup password" not in backup_json
    assert session["refreshCredential"] not in backup_json
    assert session["accessToken"] not in backup_json
    assert "backup must not contain this staged body" not in backup_json
    assert "device_req_pending_backup" not in backup_json
    assert "spki_new" not in backup_json
    assert "rotation_proof" not in backup_json
    assert "backup password" not in json.dumps(reopened.audit.list())
    reopened.close()


def test_refresh_rotation_and_reuse_revokes_all_credentials_for_the_device(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_alice")
    first = account.sessions.create_password_session(
        username="alice",
        password="password",
        installation={"installationId": "install_1", "displayName": "Alice", "devicePublicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
        correlation_id="cor_login",
    )
    second = account.sessions.refresh(
        refresh_credential=first["refreshCredential"],
        installation_id="install_1", device_id=first["deviceId"],
        correlation_id="cor_refresh", now="2026-08-27T00:01:00.000Z",
    )
    assert second["deviceId"] == first["deviceId"]
    assert second["refreshCredential"] != first["refreshCredential"]
    with pytest.raises(GatewayError, match="REFRESH_REUSED"):
        account.sessions.refresh(
            refresh_credential=first["refreshCredential"],
            installation_id="install_1", device_id=first["deviceId"],
            correlation_id="cor_reuse", now="2026-08-27T00:02:00.000Z",
        )
    assert account.sessions.active_refresh_credential_count(first["deviceId"]) == 0


def test_password_session_without_a_credential_verifier_fails_closed(tmp_path):
    core = _real_create_gateway_core(storage_root=tmp_path, secret_store=make_secret_store())
    account = core.open_gateway_account("acct_password_unverified")

    with pytest.raises(GatewayError) as error:
        account.sessions.create_password_session(
            username="alice",
            password="any-nonempty-password",
            installation={"installationId": "install_1", "devicePublicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
            correlation_id="cor_password_unverified",
        )

    assert error.value.code == "AUTHENTICATION_FAILED"
    assert account.sessions.active_refresh_credential_count("dev_unknown") == 0


def test_password_session_requires_verified_credentials_and_installation_binding(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_password_verified")

    with pytest.raises(GatewayError, match="AUTHENTICATION_FAILED"):
        account.sessions.create_password_session(
            username="alice", password="wrong",
            installation={"installationId": "install_1", "devicePublicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
            correlation_id="cor_password_wrong",
        )
    with pytest.raises(GatewayError, match="AUTHENTICATION_FAILED"):
        account.sessions.create_password_session(
            username="alice", password="password",
            installation={"installationId": "install_1"},
            correlation_id="cor_password_no_key",
        )

    session = account.sessions.create_password_session(
        username="alice", password="password",
        installation={"installationId": "install_1", "devicePublicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
        correlation_id="cor_password_good",
    )
    assert session["deviceId"].startswith("dev_")


def test_identity_rotation_rejects_an_arbitrary_string_as_continuity_proof(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_rotation_proof")
    account.close()

    with pytest.raises(GatewayError) as error:
        IdentityRotationService(core=core).rotate(
            account_id="acct_rotation_proof",
            previous_identity_ref="spki_initial",
            next_identity_ref="spki_new",
            signed_by_previous="arbitrary-string-is-not-a-proof",
            correlation_id="cor_rotation_proof",
        )

    assert error.value.code == "IDENTITY_ROTATION_PROOF_INVALID"


def test_identity_rotation_updates_the_tls_fingerprint_atomically(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_rotation_tls")
    account.close()

    next_fingerprint = "sha256:" + "2" * 64
    IdentityRotationService(core=core, proof_verifier=IdentityProofVerifierDouble()).rotate(
        account_id="acct_rotation_tls",
        previous_identity_ref="spki_initial",
        next_identity_ref="spki_new",
        signed_by_previous=_rotation_proof(next_tls_spki_sha256=next_fingerprint),
        correlation_id="cor_rotation_tls",
    )

    rotated = core.open_gateway_account("acct_rotation_tls")
    fingerprint = rotated.store.database.execute(
        "SELECT value FROM account_metadata WHERE key = 'tls_spki_sha256'"
    ).fetchone()[0]
    assert fingerprint == next_fingerprint
    negotiation = core._build_negotiation_response(
        {
            "negotiationId": "neg_rotation_tls",
            "protocol": {"major": 2, "minor": 1},
            "client": {
                "installationId": "install_rotation_tls", "appVersion": "2.0.0",
                "platform": "android", "platformApi": 35,
            },
            "features": {
                "auth": ["password"], "messages": ["chat-v1"],
                "attachments": ["staged-sha256-v1"], "events": ["sse-cursor-v1"],
                "deviceRequests": ["risk-queue-v1"],
            },
            "schemaHashes": {"core": core_schema_hash()},
        },
        rotated,
    )
    assert negotiation["gatewayIdentity"]["tlsSpkiSha256"] == next_fingerprint
    rotated.close()


@pytest.mark.parametrize(
    "mutate",
    [
        lambda proof: proof.update({"unexpected": True}),
        lambda proof: proof.update({"pairingGeneration": 2}),
        lambda proof: proof.update({"nextTlsSpkiSha256": "sha256:" + "0" * 64}),
        lambda proof: proof.update({"nextTlsSpkiSha256": "sha256:" + "A" * 64}),
        lambda proof: proof.update({"previousIdentityRef": "spki_other"}),
        lambda proof: proof.update({"nextIdentityRef": "spki_other"}),
    ],
)
def test_invalid_rotation_proof_leaves_identity_metadata_unchanged(tmp_path, mutate):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_invalid_rotation")
    account.close()
    proof = _rotation_proof()
    mutate(proof)

    with pytest.raises(GatewayError) as error:
        IdentityRotationService(
            core=core, proof_verifier=IdentityProofVerifierDouble()
        ).rotate(
            account_id="acct_invalid_rotation",
            previous_identity_ref="spki_initial",
            next_identity_ref="spki_new",
            signed_by_previous=proof,
            correlation_id="cor_invalid_rotation",
        )

    assert error.value.code == "IDENTITY_ROTATION_PROOF_INVALID"
    unchanged = core.open_gateway_account("acct_invalid_rotation")
    values = {
        row["key"]: row["value"] for row in unchanged.store.database.execute(
            "SELECT key, value FROM account_metadata WHERE key IN ('gateway_identity_ref', 'pairing_generation', 'tls_spki_sha256')"
        ).fetchall()
    }
    assert values == {
        "gateway_identity_ref": "spki_initial",
        "pairing_generation": "1",
        "tls_spki_sha256": "sha256:" + "0" * 64,
    }
    assert unchanged.store.database.execute(
        "SELECT COUNT(*) FROM identity_rotation_receipts"
    ).fetchone()[0] == 0
    unchanged.close()


def test_rotation_requires_a_verifier_and_rejects_a_false_signature(tmp_path):
    core = create_gateway_core(storage_root=tmp_path)
    account = core.open_gateway_account("acct_false_rotation")
    account.close()
    proof = _rotation_proof()

    with pytest.raises(GatewayError, match="IDENTITY_ROTATION_PROOF_UNVERIFIED"):
        IdentityRotationService(core=core).rotate(
            account_id="acct_false_rotation",
            previous_identity_ref="spki_initial",
            next_identity_ref="spki_new",
            signed_by_previous=proof,
            correlation_id="cor_no_verifier",
        )
    with pytest.raises(GatewayError, match="IDENTITY_ROTATION_PROOF_UNVERIFIED"):
        IdentityRotationService(
            core=core, proof_verifier=IdentityProofVerifierDouble()
        ).rotate(
            account_id="acct_false_rotation",
            previous_identity_ref="spki_initial",
            next_identity_ref="spki_new",
            signed_by_previous=_rotation_proof(signature="wrong-proof"),
            correlation_id="cor_false_signature",
        )
