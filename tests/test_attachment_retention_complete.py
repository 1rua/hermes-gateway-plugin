"""Application-managed attachment bytes must disappear, including trash copies."""
import asyncio
import hashlib
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from open_android_intelligence_gateway import adapter as adapter_module
from open_android_intelligence_gateway.core import AttachmentStore, create_gateway_core
from test_support import make_secret_store


def test_idle_attachment_expires_in_real_maintenance_without_being_read(tmp_path):
    core = create_gateway_core(tmp_path / "data", secret_store=make_secret_store())
    account = core.open_gateway_account("acct_idle")
    content = b"sensitive attachment body"
    aid = account.attachments.create(
        clientAttachmentId="ca_idle", filename="private.txt", mediaType="text/plain",
        sizeBytes=len(content), sha256=hashlib.sha256(content).hexdigest(), correlationId="cor_idle",
    )["attachmentId"]
    account.attachments.upload_content(aid, content)
    row = account.store.database.execute("SELECT content_path FROM attachments WHERE attachment_id = ?", (aid,)).fetchone()
    payload_path = Path(row[0])
    account.store.database.execute("UPDATE attachments SET expires_at = ?, storage_revision = storage_revision + 1 WHERE attachment_id = ?", ("2020-01-01T00:00:00.000Z", aid))
    account.close()
    adapter = adapter_module.OpenAndroidPlatformAdapter.__new__(adapter_module.OpenAndroidPlatformAdapter)
    adapter.services = SimpleNamespace(core=core)
    adapter._running = True
    adapter._recovery_account_ids = lambda: ["acct_idle"]
    async def one_tick(_):
        adapter._running = False
    trash = tmp_path / "trash"
    trash.mkdir()
    with patch.object(adapter_module.asyncio, "sleep", one_tick), patch.object(AttachmentStore, "_trash_root", return_value=trash):
        asyncio.run(adapter._maintain_accounts())
    reopened = core.open_gateway_account("acct_idle")
    try:
        state = reopened.store.database.execute("SELECT state FROM attachments WHERE attachment_id = ?", (aid,)).fetchone()[0]
        assert state in {"expired", "deleted"}
        assert not payload_path.exists()
        assert list(trash.iterdir()) == []
    finally:
        reopened.close()
