"""Hermes plugin entry point.

The host imports this module and calls ``register(ctx)``. It sits at the
repository root because a checkout installed as a plugin directory is loaded
from there, and it puts that root on ``sys.path`` so the package sitting next to
it can be imported by name — without that, the import would depend on the
host happening to have added the plugin directory itself.

No path is hardcoded: everything is derived from this file, so the plugin works
wherever it is installed.
"""

import sys
from pathlib import Path

_PLUGIN_ROOT = Path(__file__).resolve().parent
if str(_PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_ROOT))

from open_android_intelligence_gateway.plugin import (  # noqa: E402
    HERMES_PLUGIN,
    HERMES_PLUGIN_MANIFEST,
    register,
)

__all__ = ["register", "HERMES_PLUGIN", "HERMES_PLUGIN_MANIFEST"]
