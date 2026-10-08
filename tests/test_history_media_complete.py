from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from open_android_intelligence_gateway.core import GatewayError, create_gateway_core
from open_android_intelligence_gateway.history_media import HistoryMedia
from test_support import make_secret_store


def test_host_originals_have_scoped_single_use_expiring_grants_and_unavailable_metadata(tmp_path, monkeypatch):
    host_home = tmp_path / "hermes_home"
    monkeypatch.setenv("HERMES_HOME", str(host_home))
    output = host_home / "outputs" / "history.txt"
    output.parent.mkdir(parents=True)
    output.write_bytes(b"private native historical media")
    core = create_gateway_core(tmp_path / "gateway", secret_store=make_secret_store())
    account = core.open_gateway_account("acct_media")
    other = core.open_gateway_account("acct_other")
    context = {"deviceId": "dev_media", "pairingGeneration": 2, "grantRevision": 3}
    now = datetime.now(timezone.utc)
    try:
        cid = account.conversations.create("cc_media", "Media", "cor_media")["conversationId"]
        media = HistoryMedia(account)
        attachment_id = media.register(cid, "msg_media", output)["attachmentId"]
        assert media.metadata(cid, attachment_id)["remoteAvailable"]
        assert "path" not in media.metadata(cid, attachment_id)
        token = media.grant(cid, attachment_id, context, now)["grantId"]
        for change in ({"deviceId": "dev_other"}, {"pairingGeneration": 1}, {"grantRevision": 4}):
            with pytest.raises(GatewayError, match="AUTHENTICATION_FAILED"):
                media.content(cid, attachment_id, token, context | change, now)
        with pytest.raises(GatewayError, match="ATTACHMENT_NOT_FOUND"):
            HistoryMedia(other).metadata(cid, attachment_id)
        assert media.content(cid, attachment_id, token, context, now) == (output.read_bytes(), "text/plain")
        with pytest.raises(GatewayError, match="AUTHENTICATION_FAILED"):
            media.content(cid, attachment_id, token, context, now)
        expired = media.grant(cid, attachment_id, context, now)["grantId"]
        with pytest.raises(GatewayError, match="AUTHENTICATION_FAILED"):
            media.content(cid, attachment_id, expired, context, now + timedelta(seconds=121))
        # Equal-sized replacement is unavailable too; metadata remains readable.
        output.write_bytes(b"x" * output.stat().st_size)
        assert media.metadata(cid, attachment_id)["status"] == "REMOTE_UNAVAILABLE"
        output.unlink()
        assert not media.metadata(cid, attachment_id)["remoteAvailable"]
    finally:
        account.close()
        other.close()
