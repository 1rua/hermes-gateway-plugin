import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from open_android_intelligence_gateway.admin import run_admin_command
from open_android_intelligence_gateway.plugin import HERMES_PLUGIN_MANIFEST, register
from test_support import PasswordVerifierDouble


class FakeHermesContext:
    def __init__(self, plugin_data_dir, host_version="1.0.0"):
        self.plugin_data_dir = plugin_data_dir
        self.secret_store = None
        self.credential_verifier = PasswordVerifierDouble()
        self.host_version = host_version
        self.platform_ids = []
        self.platforms = []
        self.admin_surfaces = []
        self.http_routes = []
        self.cli_registrations = []

    def register_platform(self, platform):
        self.platform_ids.append(platform.platform_id)
        self.platforms.append(platform)

    def register_admin(self, admin):
        self.admin_surfaces.append(admin)

    def register_http_route(self, route):
        self.http_routes.append(route)

    def register_cli(self, registrar, options):
        self.cli_registrations.append((registrar, options))


def test_registers_platform_and_management_surface(tmp_path):
    context = FakeHermesContext(tmp_path)

    register(context)

    assert HERMES_PLUGIN_MANIFEST["version"] == "2.1.0"
    assert context.platform_ids == ["open-android-intelligence-gateway"]
    assert len(context.admin_surfaces) == 1


def test_registration_exposes_native_core_routes_and_local_only_management(tmp_path):
    context = FakeHermesContext(tmp_path)

    register(context)

    platform = context.platforms[0]
    assert platform.id == "open-android-intelligence-gateway"
    assert platform is not context.admin_surfaces[0].panel
    assert platform.core is context.admin_surfaces[0].panel.service.core
    assert platform.core.credential_verifier is context.credential_verifier
    assert platform.read_only is True
    platform_result = platform.handle({
        "context": {"requestId": "req_platform", "correlationId": "cor_platform"}
    })
    assert platform_result["error"]["code"] == "HOST_INCOMPATIBLE"
    assert context.admin_surfaces[0].remote_port is None
    assert context.admin_surfaces[0].local_only is True
    assert {route["path"] for route in context.http_routes} >= {
        "/open-android-intelligence/v2/negotiate",
        "/open-android-intelligence/v2/events",
        "/open-android-intelligence/v2/attachments",
        "/open-android-intelligence/v2/device-requests/",
    }
    assert context.cli_registrations[0][1]["commands"] == ["open-android-intelligence"]


def test_registration_marks_unknown_host_read_only_before_writes(tmp_path):
    context = FakeHermesContext(tmp_path, host_version="not-a-version")

    register(context)

    assert context.admin_surfaces[0].read_only is True
    result = context.admin_surfaces[0].create_account({"accountId": "acct", "localConfirmation": True})
    assert result["error"]["code"] == "HOST_INCOMPATIBLE"
    assert not (Path(tmp_path) / "open-android-intelligence-gateway" / "accounts").exists()


def test_registered_no_argument_cli_reuses_the_panel_admin_service(tmp_path):
    context = FakeHermesContext(tmp_path)

    register(context)

    panel = context.admin_surfaces[0].panel
    assert run_admin_command(["status"]) == panel.status()


def test_registration_resolves_verified_hermes_host_api(tmp_path):
    class PluginContext:
        def __init__(self, plugin_data_dir, host_version="0.20.0"):
            self.plugin_data_dir = plugin_data_dir
            self.secret_store = None
            self.credential_verifier = PasswordVerifierDouble()
            self.host_version = host_version
            self.platforms = []
            self.admin_surfaces = []
            self.http_routes = []
            self.cli_registrations = []

        def register_platform(self, platform):
            self.platforms.append(platform)

        def register_admin(self, admin):
            self.admin_surfaces.append(admin)

        def register_http_route(self, route):
            self.http_routes.append(route)

        def register_cli(self, registrar, options):
            self.cli_registrations.append((registrar, options))

    ctx = PluginContext(tmp_path)
    register(ctx)
    assert ctx.admin_surfaces[0].read_only is False
