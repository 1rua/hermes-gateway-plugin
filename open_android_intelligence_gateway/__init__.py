"""Open Android Intelligence Gateway Protocol v2 package."""

from .core import GatewayCore, create_gateway_core
from .adapter import OpenAndroidPlatformAdapter, LocalCredentialVerifier
from .plugin import (
    register,
    HERMES_PLUGIN,
    HERMES_PLUGIN_MANIFEST,
    GatewayPlatform,
    AdminSurface,
    GatewayServices,
    compose_gateway_services,
)

__all__ = [
    "GatewayCore",
    "create_gateway_core",
    "OpenAndroidPlatformAdapter",
    "LocalCredentialVerifier",
    "register",
    "HERMES_PLUGIN",
    "HERMES_PLUGIN_MANIFEST",
    "GatewayPlatform",
    "AdminSurface",
    "GatewayServices",
    "compose_gateway_services",
]

