#!/usr/bin/env python3
"""Gate for the things pytest cannot see on its own.

Three claims are checked here, each of which has bitten this plugin before: the
manifest declares what the host needs in order to load it, the package exports
the entry point the host calls, and the protocol version the manifest
advertises is the one the core actually negotiates. The last one is the
cross-repository drift guard - the plugin and the application release
independently, so nothing else would fail if the two disagreed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
REQUIRED_FIELDS = ("name", "version", "description", "kind")


def main() -> int:
    manifest = yaml.safe_load((PLUGIN_ROOT / "plugin.yaml").read_text(encoding="utf-8"))
    missing = [field for field in REQUIRED_FIELDS if not manifest.get(field)]
    if missing:
        print("plugin.yaml missing required fields: " + ", ".join(missing))
        return 1

    sys.path.insert(0, str(PLUGIN_ROOT))
    from open_android_intelligence_gateway.plugin import (
        HERMES_PLUGIN_MANIFEST,
        register,
        verify_manifest_protocol,
    )

    if not callable(register):
        print("the plugin package does not export register(ctx)")
        return 1
    try:
        verify_manifest_protocol(HERMES_PLUGIN_MANIFEST)
    except Exception as exc:
        print("protocol declaration rejected: " + str(exc))
        return 1

    pin = json.loads((PLUGIN_ROOT / "contract-pin.json").read_text(encoding="utf-8"))
    revision = str(pin.get("revision") or "")
    if len(revision) != 40:
        print("contract-pin.json revision must be a 40 character commit, got: " + (revision or "(empty)"))
        return 1

    print(
        "manifest and entry point OK: "
        + manifest["name"] + " " + manifest["version"]
        + " (kind=" + manifest["kind"]
        + ", protocol=" + HERMES_PLUGIN_MANIFEST["protocolVersion"]
        + ", contract=" + revision[:12] + ")"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
