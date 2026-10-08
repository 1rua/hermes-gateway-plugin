"""The manifest must not be able to drift away from the wire protocol.

The plugin repository and the application repository now release
independently, so the manifest's declared protocol version and the core's
negotiated protocol version can diverge silently: nothing in a single
repository would fail, and the mismatch would only surface on a phone as
``PROTOCOL_INCOMPATIBLE`` during negotiation. Refusing to load turns that
late, confusing failure into an immediate, stated one.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from open_android_intelligence_gateway.core import PROTOCOL_VERSION
from open_android_intelligence_gateway import plugin as plugin_module
from open_android_intelligence_gateway.plugin import (
    HERMES_PLUGIN_MANIFEST,
    ManifestProtocolMismatch,
    verify_manifest_protocol,
)


def test_accepts_a_manifest_whose_protocol_matches_the_core():
    verify_manifest_protocol(HERMES_PLUGIN_MANIFEST)


def test_refuses_a_manifest_whose_protocol_drifted_from_the_core():
    drifted = {**HERMES_PLUGIN_MANIFEST, "protocolVersion": "9.9.9"}

    with pytest.raises(ManifestProtocolMismatch) as mismatch:
        verify_manifest_protocol(drifted)

    reported = str(mismatch.value)
    assert "9.9.9" in reported
    core_label = f"{PROTOCOL_VERSION['major']}.{PROTOCOL_VERSION['minor']}"
    assert core_label in reported


def test_register_refuses_to_load_a_host_on_a_drifted_manifest(monkeypatch):
    monkeypatch.setattr(
        plugin_module,
        "HERMES_PLUGIN_MANIFEST",
        {**HERMES_PLUGIN_MANIFEST, "protocolVersion": "9.9.9"},
    )

    with pytest.raises(ManifestProtocolMismatch):
        plugin_module.register(object())