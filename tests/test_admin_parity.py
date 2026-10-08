import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from open_android_intelligence_gateway.admin import (
    HERMES_HOST_API,
    HostApiCompatibility,
    create_admin_cli_registrar,
    create_admin_panel,
    create_admin_service,
    is_host_api_compatible,
    run_admin_command,
)


class Command:
    def __init__(self, name):
        self.name = name
        self.children = []
        self.options = []
        self.description_text = None
        self.action_handler = None

    def command(self, spec):
        child = Command(spec.split()[0])
        self.children.append(child)
        return child

    def description(self, value):
        self.description_text = value
        return self

    def option(self, flags, description=None):
        self.options.append(flags)
        return self

    def action(self, handler):
        self.action_handler = handler
        return self


def find_command(root, names):
    current = root
    for name in names:
        current = next(child for child in current.children if child.name == name)
    return current


def test_admin_panel_and_local_cli_share_confirmed_write_semantics(tmp_path):
    service = create_admin_service(
        storage_root=tmp_path,
        host_version="1.0.0",
        host_api=HostApiCompatibility("1.0.0", "1.0.0", "0123456789abcdef0123456789abcdef01234567"),
    )
    panel = create_admin_panel(service)
    program = Command("hermes")
    create_admin_cli_registrar(service)(program)

    create = find_command(program, ["open-android-intelligence", "account", "create"])
    status = find_command(program, ["open-android-intelligence", "account", "status"])
    delete = find_command(program, ["open-android-intelligence", "account", "delete"])
    assert program.children[0].description_text == "Manage Open Android Intelligence Gateway accounts"
    assert "--confirm-local" in create.options
    assert "--confirm-local" in delete.options
    assert "--password <password>" in create.options

    without_confirmation = panel.create_account({"accountId": "account-a", "password": "pw"})
    assert without_confirmation["error"]["code"] == "LOCAL_CONFIRMATION_REQUIRED"
    assert create.action_handler("account-a", {"password": "pw"})["error"]["code"] == "LOCAL_CONFIRMATION_REQUIRED"

    without_password = panel.create_account({"accountId": "account-a", "localConfirmation": True})
    assert without_password["error"]["code"] == "PASSWORD_REQUIRED"

    ui_create = panel.create_account({"accountId": "account-a", "password": "pw", "localConfirmation": True})
    cli_create = create.action_handler("account-a", {"confirmLocal": True, "password": "pw"})
    assert ui_create["ok"] is True
    assert cli_create["error"]["code"] == "ACCOUNT_EXISTS"
    assert cli_create == panel.create_account({"accountId": "account-a", "password": "pw", "localConfirmation": True})
    assert status.action_handler() == panel.status()
    assert run_admin_command(["account", "status"], service=service) == panel.status()

    # Deletion is a real resource-level operation on both surfaces, and it is
    # gated by the same read-only and local-confirmation rules as creation.
    assert delete.action_handler("account-a", {"confirmLocal": True})["ok"] is True
    assert panel.delete_account({"accountId": "account-a", "localConfirmation": True})["error"]["code"] == "ACCOUNT_NOT_FOUND"


def test_incompatible_hermes_host_keeps_panel_and_cli_read_only(tmp_path):
    service = create_admin_service(storage_root=tmp_path, host_version="2.0.0")
    panel = create_admin_panel(service)
    assert panel.read_only is True
    result = panel.create_account({"accountId": "account-a", "localConfirmation": True})
    assert result["readOnly"] is True
    assert result["error"]["code"] == "HOST_INCOMPATIBLE"
    assert service.status()["data"]["readOnly"] is True
    assert HERMES_HOST_API.verified_commit == ""


def test_admin_status_uses_openclaw_canonical_host_field_names(tmp_path):
    service = create_admin_service(
        storage_root=tmp_path,
        host_version="1.0.0",
        host_api=HostApiCompatibility("1.0.0", "1.0.0", "0123456789abcdef0123456789abcdef01234567"),
    )

    status = service.status()

    assert set(status["data"]) == {
        "hostVersion", "minHostVersion", "maxHostVersion", "verifiedHostCommit", "readOnly",
    }


def test_default_hermes_host_api_is_explicitly_unverified_and_never_compatible():
    assert HERMES_HOST_API.verified_commit == ""
    assert is_host_api_compatible("1.0.0", HERMES_HOST_API) is False
