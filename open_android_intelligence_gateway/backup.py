"""Portable, non-secret Gateway account backups."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .core import GatewayCore, iso_millis


class GatewayBackupService:
    def __init__(self, storage_root: str | Path | None = None, core: GatewayCore | None = None):
        self.core = core or GatewayCore(storage_root=storage_root)

    def export_portable(self, account_id: str, now: datetime | str | None = None) -> dict[str, Any]:
        account = self.core.open_gateway_account(account_id)
        try:
            rows = account.store.database.execute(
                """
                SELECT attachment_id, filename, media_type, size_bytes, sha256, state
                FROM attachments
                WHERE state IN ('verified', 'delivered', 'acknowledged', 'failed', 'expired', 'deleted')
                ORDER BY attachment_id
                """
            ).fetchall()
            attachments = [
                {
                    "attachmentId": row["attachment_id"], "filename": row["filename"],
                    "mediaType": row["media_type"], "sizeBytes": int(row["size_bytes"]),
                    "sha256": row["sha256"], "state": row["state"],
                }
                for row in rows
            ]
            conversations = [
                {
                    "conversationId": row["conversation_id"],
                    "clientConversationId": row["client_conversation_id"],
                    "title": row["title"],
                }
                for row in account.store.database.execute(
                    "SELECT conversation_id, client_conversation_id, title FROM conversations ORDER BY conversation_id"
                ).fetchall()
            ]
            plugins = [
                {"pluginId": row["plugin_id"], "manifest": row["manifest_json"]}
                for row in account.store.database.execute("SELECT plugin_id, manifest_json FROM plugin_registry ORDER BY plugin_id").fetchall()
            ]
            audit = [
                record for record in account.audit.list()
                if record["eventType"] != "device.request.enqueued"
            ]
            return {
                "format": "open-android-intelligence-gateway-portable-backup-v1",
                "accountId": account_id,
                "exportedAt": iso_millis(now),
                "masterKeyContinuitySha256": hashlib.sha256(account.master_key_ref.encode("utf-8")).hexdigest(),
                "plugins": plugins,
                "attachments": attachments,
                "conversations": conversations,
                "audit": audit,
            }
        finally:
            account.close()

    # Camel-case alias keeps the host-facing service naming interoperable.
    exportPortable = export_portable


def export_portable_backup(account_id: str, storage_root: str | Path | None = None) -> dict[str, Any]:
    return GatewayBackupService(storage_root=storage_root).export_portable(account_id)
