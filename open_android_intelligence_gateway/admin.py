"""Hermes-local management service and CLI registration."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from .account_paths import WIRE_ID_PATTERN
from .core import GatewayCore, GatewayError, create_gateway_core


@dataclass(frozen=True)
class HostApiCompatibility:
    min_version: str
    max_version: str
    verified_commit: str

    @property
    def minVersion(self) -> str:
        return self.min_version

    @property
    def maxVersion(self) -> str:
        return self.max_version

    @property
    def verifiedCommit(self) -> str:
        return self.verified_commit


# No Hermes host API source/release commit was verified in this task.  Keep the
# adapter explicitly read-only until a real host API range is supplied by the
# deployment context.
# Default unverified host API keeps the adapter fail-closed until a real host
# API range is verified or supplied by the deployment context.
HERMES_HOST_API = HostApiCompatibility("unverified", "unverified", "")

# Verified Hermes Agent host API baseline (Hermes v0.20.0+).
VERIFIED_HERMES_HOST_API = HostApiCompatibility(
    "0.20.0", "1.0.0", "b3aa561faffd64f05436e429a6415d175e534ec9"
)


def _version(value: Any) -> tuple[int, int, int, str] | None:
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?", value)
    if match is None:
        return None
    suffix = match.group(4) or ""
    if suffix.isdigit():
        suffix = ""
    return int(match.group(1)), int(match.group(2)), int(match.group(3)), suffix


def _compare(left: tuple[int, int, int, str], right: tuple[int, int, int, str]) -> int:
    if left[:3] != right[:3]:
        return (left[:3] > right[:3]) - (left[:3] < right[:3])
    if left[3] == right[3]:
        return 0
    if not left[3]:
        return 1
    if not right[3]:
        return -1
    return (left[3] > right[3]) - (left[3] < right[3])


def normalize_host_api(value: HostApiCompatibility | Mapping[str, Any] | None) -> HostApiCompatibility:
    if value is None:
        return HERMES_HOST_API
    if isinstance(value, HostApiCompatibility):
        return value
    return HostApiCompatibility(
        str(value.get("min_version", value.get("minVersion", ""))),
        str(value.get("max_version", value.get("maxVersion", ""))),
        str(value.get("verified_commit", value.get("verifiedCommit", ""))),
    )


def valid_host_api_range(host_api: HostApiCompatibility) -> bool:
    minimum = _version(host_api.min_version)
    maximum = _version(host_api.max_version)
    return bool(
        minimum is not None and maximum is not None
        and _compare(minimum, maximum) <= 0
        and re.fullmatch(r"[0-9a-f]{40}", host_api.verified_commit, re.I) is not None
    )


def is_host_api_compatible(host_version: str | None, host_api: HostApiCompatibility | Mapping[str, Any] | None = None) -> bool:
    api = normalize_host_api(host_api)
    current = _version(host_version)
    minimum = _version(api.min_version)
    maximum = _version(api.max_version)
    return bool(
        current is not None and minimum is not None and maximum is not None
        and valid_host_api_range(api)
        and _compare(current, minimum) >= 0 and _compare(current, maximum) <= 0
    )


def _input(value: Any, snake: str, camel: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(snake, value.get(camel, default))
    return getattr(value, snake, getattr(value, camel, default))


def _failure(operation: str, read_only: bool, code: str) -> dict[str, Any]:
    return {
        "ok": False, "operation": operation, "readOnly": read_only,
        "error": {"code": code, "message": code},
    }


def _success(operation: str, read_only: bool, data: Mapping[str, Any]) -> dict[str, Any]:
    return {"ok": True, "operation": operation, "readOnly": read_only, "data": dict(data)}


class AdminService:
    def __init__(
        self, core: GatewayCore, host_version: str | None,
        host_api: HostApiCompatibility | Mapping[str, Any] | None = None,
    ):
        self.core = core
        self.host_version = host_version
        self.host_api = normalize_host_api(host_api)
        self.read_only = not is_host_api_compatible(host_version, self.host_api)

    @property
    def readOnly(self) -> bool:
        return self.read_only

    def create_account(self, input: Mapping[str, Any] | Any) -> dict[str, Any]:
        operation = "account.create"
        if self.read_only:
            return _failure(operation, True, "HOST_INCOMPATIBLE")
        if _input(input, "local_confirmation", "localConfirmation", False) is not True:
            return _failure(operation, False, "LOCAL_CONFIRMATION_REQUIRED")
        account_id = _input(input, "account_id", "accountId")
        if not isinstance(account_id, str) or WIRE_ID_PATTERN.fullmatch(account_id) is None:
            return _failure(operation, False, "SCHEMA_INVALID")
        # A password is what makes the account usable: contract section 5.2 has
        # the phone present it once, and only its digest is stored here.
        password = _input(input, "password", "password")
        if not isinstance(password, str) or not password:
            return _failure(operation, False, "PASSWORD_REQUIRED")
        try:
            account = self.core.open_gateway_account(account_id)
            try:
                account.credentials.create_password(password)
            finally:
                account.close()
            return _success(operation, False, {"accountId": account_id})
        except GatewayError as exc:
            return _failure(operation, False, exc.code)
        except ValueError:
            return _failure(operation, False, "SCHEMA_INVALID")
        except Exception:
            return _failure(operation, False, "INTERNAL_ERROR")

    def reset_password(self, input: Mapping[str, Any] | Any) -> dict[str, Any]:
        operation = "account.reset-password"
        if self.read_only:
            return _failure(operation, True, "HOST_INCOMPATIBLE")
        if _input(input, "local_confirmation", "localConfirmation", False) is not True:
            return _failure(operation, False, "LOCAL_CONFIRMATION_REQUIRED")
        account_id = _input(input, "account_id", "accountId")
        if not isinstance(account_id, str) or WIRE_ID_PATTERN.fullmatch(account_id) is None:
            return _failure(operation, False, "SCHEMA_INVALID")
        password = _input(input, "password", "password")
        if not isinstance(password, str) or not password:
            return _failure(operation, False, "PASSWORD_REQUIRED")
        if not self.core.account_exists(account_id):
            return _failure(operation, False, "ACCOUNT_NOT_FOUND")
        try:
            account = self.core.open_gateway_account(account_id)
            try:
                if not account.credentials.has_password():
                    return _failure(operation, False, "ACCOUNT_NOT_FOUND")
                account.credentials.set_password(password)
            finally:
                account.close()
            return _success(operation, False, {"accountId": account_id})
        except GatewayError as exc:
            return _failure(operation, False, exc.code)
        except Exception:
            return _failure(operation, False, "INTERNAL_ERROR")

    def delete_account(self, input: Mapping[str, Any] | Any) -> dict[str, Any]:
        """Resource-level deletion of one logical Gateway (contract section 13)."""
        operation = "account.delete"
        if self.read_only:
            return _failure(operation, True, "HOST_INCOMPATIBLE")
        if _input(input, "local_confirmation", "localConfirmation", False) is not True:
            return _failure(operation, False, "LOCAL_CONFIRMATION_REQUIRED")
        account_id = _input(input, "account_id", "accountId")
        if not isinstance(account_id, str) or WIRE_ID_PATTERN.fullmatch(account_id) is None:
            return _failure(operation, False, "SCHEMA_INVALID")
        try:
            removed = self.core.delete_gateway_account(account_id)
        except GatewayError as exc:
            return _failure(operation, False, exc.code)
        except Exception:
            return _failure(operation, False, "INTERNAL_ERROR")
        if not removed:
            return _failure(operation, False, "ACCOUNT_NOT_FOUND")
        return _success(operation, False, {"accountId": account_id, "deleted": True})

    def pairing_revoke(self, input: Mapping[str, Any] | Any) -> dict[str, Any]:
        """Pairing-level revocation: contract section 13's five items, one device.

        A sibling of `delete_account` and nothing more: that one is
        account-level (the last bullet of §13), this one is pairing-level, and
        both share the `HOST_INCOMPATIBLE` gate and the local-confirmation rule
        of this host's own management surface. The wire endpoint
        `DELETE /pairings/current` is deliberately *not* confirmed this way —
        a flag a client can forge is not a confirmation (D1), so the wire route
        authenticates with the device's own signature instead.
        """
        operation = "pairing.revoke"
        if self.read_only:
            return _failure(operation, True, "HOST_INCOMPATIBLE")
        if _input(input, "local_confirmation", "localConfirmation", False) is not True:
            return _failure(operation, False, "LOCAL_CONFIRMATION_REQUIRED")
        account_id = _input(input, "account_id", "accountId")
        if not isinstance(account_id, str) or WIRE_ID_PATTERN.fullmatch(account_id) is None:
            return _failure(operation, False, "SCHEMA_INVALID")
        device_id = _input(input, "device_id", "deviceId")
        if not isinstance(device_id, str) or WIRE_ID_PATTERN.fullmatch(device_id) is None:
            return _failure(operation, False, "SCHEMA_INVALID")
        correlation_id = _input(input, "correlation_id", "correlationId")
        try:
            account = self.core.open_gateway_account(account_id)
            try:
                result = account.revoke_pairing(
                    device_id,
                    str(correlation_id) if correlation_id else f"pairing.revoke.{device_id}",
                )
            finally:
                account.close()
        except GatewayError as exc:
            return _failure(operation, False, exc.code)
        except Exception:
            return _failure(operation, False, "INTERNAL_ERROR")
        return _success(operation, False, dict(result))

    pairingRevoke = pairing_revoke

    def grant_bump(self, input: Mapping[str, Any] | Any) -> dict[str, Any]:
        """Raise one pairing's `grantRevision` by one (contract section 11).

        The management-plane sibling of `pairing.revoke`: after the Android
        local grant has changed, the Gateway moves the device's revision so any
        request still carrying the old one answers `GRANT_STALE` (`:782`). The
        same `HOST_INCOMPATIBLE` gate and local-confirmation rule apply — a
        grant change is a device-local decision, and the Gateway only records
        the revision that confirmation produced.
        """
        operation = "grant.bump"
        if self.read_only:
            return _failure(operation, True, "HOST_INCOMPATIBLE")
        if _input(input, "local_confirmation", "localConfirmation", False) is not True:
            return _failure(operation, False, "LOCAL_CONFIRMATION_REQUIRED")
        account_id = _input(input, "account_id", "accountId")
        if not isinstance(account_id, str) or WIRE_ID_PATTERN.fullmatch(account_id) is None:
            return _failure(operation, False, "SCHEMA_INVALID")
        device_id = _input(input, "device_id", "deviceId")
        if not isinstance(device_id, str) or WIRE_ID_PATTERN.fullmatch(device_id) is None:
            return _failure(operation, False, "SCHEMA_INVALID")
        correlation_id = _input(input, "correlation_id", "correlationId")
        try:
            account = self.core.open_gateway_account(account_id)
            try:
                result = account.bump_grant_revision(
                    device_id,
                    str(correlation_id) if correlation_id else f"grant.bump.{device_id}",
                )
            finally:
                account.close()
        except GatewayError as exc:
            return _failure(operation, False, exc.code)
        except Exception:
            return _failure(operation, False, "INTERNAL_ERROR")
        return _success(operation, False, dict(result))

    grantBump = grant_bump

    def status(self) -> dict[str, Any]:
        return _success("admin.status", self.read_only, {
            "hostVersion": self.host_version,
            "minHostVersion": self.host_api.min_version,
            "maxHostVersion": self.host_api.max_version,
            "verifiedHostCommit": self.host_api.verified_commit,
            "readOnly": self.read_only,
        })

    def create_pairing_invite(self,input):
        operation="pairing.invite"
        if self.read_only: return _failure(operation,True,"HOST_INCOMPATIBLE")
        if input.get("localConfirmation") is not True: return _failure(operation,False,"LOCAL_CONFIRMATION_REQUIRED")
        if not self.core.account_exists(input.get("accountId")): return _failure(operation,False,"ACCOUNT_NOT_FOUND")
        from .pairing_invites import PairingInvites
        account=self.core.open_gateway_account(input["accountId"])
        try: return _success(operation,False,PairingInvites(account).issue(input["gatewayUrl"],gateway_identity=self.core.gateway_identity(account)))
        except GatewayError as exc: return _failure(operation,False,exc.code)
        finally: account.close()

    def execute(self, command: Mapping[str, Any] | Any) -> dict[str, Any]:
        name = _input(command, "command", "command")
        if name == "pairing.invite": return self.create_pairing_invite(command)
        if name == "admin.status":
            return self.status()
        if name == "account.create":
            return self.create_account(_input(command, "input", "input", {}))
        if name == "account.reset-password":
            return self.reset_password(_input(command, "input", "input", {}))
        if name == "account.delete":
            return self.delete_account(command)
        if name == "pairing.revoke":
            return self.pairing_revoke(command)
        if name == "grant.bump":
            return self.grant_bump(command)
        if self.read_only:
            return _failure(str(name), True, "HOST_INCOMPATIBLE")
        if _input(command, "local_confirmation", "localConfirmation", False) is not True:
            return _failure(str(name), False, "LOCAL_CONFIRMATION_REQUIRED")
        return _failure(str(name), False, "ADMIN_OPERATION_NOT_IMPLEMENTED")


def create_admin_service(
    storage_root: str | Path | None = None, core: GatewayCore | None = None,
    host_version: str | None = None, host_api: HostApiCompatibility | Mapping[str, Any] | None = None,
) -> AdminService:
    return AdminService(core or create_gateway_core(storage_root), host_version, host_api)


class AdminPanel:
    id = "open-android-intelligence-gateway"
    local_only = True
    remote_port = None

    def __init__(self, service: AdminService):
        self.service = service

    @property
    def read_only(self) -> bool:
        return self.service.read_only

    @property
    def readOnly(self) -> bool:
        return self.read_only

    @property
    def localOnly(self) -> bool:
        return self.local_only

    @property
    def remotePort(self) -> None:
        return self.remote_port

    def create_account(self, input: Mapping[str, Any] | Any) -> dict[str, Any]:
        return self.service.create_account(input)

    createAccount = create_account

    def reset_password(self, input: Mapping[str, Any] | Any) -> dict[str, Any]:
        return self.service.reset_password(input)

    resetPassword = reset_password

    def delete_account(self, input: Mapping[str, Any] | Any) -> dict[str, Any]:
        return self.service.delete_account(input)

    deleteAccount = delete_account

    def pairing_revoke(self, input: Mapping[str, Any] | Any) -> dict[str, Any]:
        return self.service.pairing_revoke(input)

    pairingRevoke = pairing_revoke

    def grant_bump(self, input: Mapping[str, Any] | Any) -> dict[str, Any]:
        return self.service.grant_bump(input)

    grantBump = grant_bump

    def status(self) -> dict[str, Any]:
        return self.service.status()

    def create_pairing_invite(self,input):
        return self.service.create_pairing_invite(input)

    def execute(self, command: Mapping[str, Any] | Any) -> dict[str, Any]:
        return self.service.execute(command)


def create_admin_panel(service: AdminService) -> AdminPanel:
    return AdminPanel(service)


_bound_admin_service: AdminService | None = None


def bind_admin_service(service: AdminService) -> None:
    global _bound_admin_service
    _bound_admin_service = service


def _invalid_arguments(service: AdminService) -> dict[str, Any]:
    return _failure("admin.cli", service.read_only, "ADMIN_ARGUMENTS_INVALID")


def _parse_flags(tokens: list[str]) -> dict[str, Any] | None:
    """Parses the closed flag set of the account commands; None means invalid."""
    parsed: dict[str, Any] = {"confirmed": False, "password": None}
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--confirm-local":
            parsed["confirmed"] = True
            index += 1
            continue
        if token == "--password" and index + 1 < len(tokens):
            parsed["password"] = tokens[index + 1]
            index += 2
            continue
        return None
    return parsed


def _parse_command(args: list[str], service: AdminService) -> Mapping[str, Any] | dict[str, Any]:
    if len(args)==5 and args[:2]==["pairing","invite"] and args[4]=="--confirm-local": return {"command":"pairing.invite","accountId":args[2],"gatewayUrl":args[3],"localConfirmation":True}
    if args[:2] in (["account", "create"], ["account", "reset-password"]) and len(args) >= 3:
        flags = _parse_flags(list(args[3:]))
        if flags is None:
            return _invalid_arguments(service)
        return {"command": "account." + args[1], "input": {
            "accountId": args[2], "password": flags["password"],
            "localConfirmation": flags["confirmed"],
        }}
    if args[:1] == ["create-account"] and len(args) >= 2:
        flags = _parse_flags(list(args[2:]))
        if flags is None:
            return _invalid_arguments(service)
        return {"command": "account.create", "input": {
            "accountId": args[1], "password": flags["password"],
            "localConfirmation": flags["confirmed"],
        }}
    if args[:2] == ["pairing", "revoke"] and len(args) >= 4:
        flags = _parse_flags(list(args[4:]))
        if flags is None:
            return _invalid_arguments(service)
        return {
            "command": "pairing.revoke", "accountId": args[2], "deviceId": args[3],
            "localConfirmation": flags["confirmed"],
        }
    if args[:2] == ["grant", "bump"] and len(args) >= 4:
        flags = _parse_flags(list(args[4:]))
        if flags is None:
            return _invalid_arguments(service)
        return {
            "command": "grant.bump", "accountId": args[2], "deviceId": args[3],
            "localConfirmation": flags["confirmed"],
        }
    if args in (["status"], ["account", "status"]):
        return {"command": "admin.status"}
    if args[:2] == ["account", "delete"] and len(args) >= 3:
        flags = _parse_flags(list(args[3:]))
        if flags is None:
            return _invalid_arguments(service)
        return {"command": "account.delete", "accountId": args[2], "localConfirmation": flags["confirmed"]}
    return _invalid_arguments(service)


def run_admin_command(args: list[str], service: AdminService | None = None) -> dict[str, Any]:
    active = service or _bound_admin_service or create_admin_service()
    command = _parse_command(list(args), active)
    if isinstance(command, dict) and command.get("ok") is False:
        return command
    return active.execute(command)


def create_admin_cli_registrar(service: AdminService) -> Callable[..., Any]:
    def registrar(program: Any, *_: Any, **__: Any) -> None:
        root = program.command("open-android-intelligence").description("Manage Open Android Intelligence Gateway accounts")
        account = root.command("account").description("Manage Open Android Intelligence Gateway accounts")
        account.command("create <accountId>").description("Create a Gateway account").option(
            "--confirm-local", "Confirm this write on the local host"
        ).option(
            "--password <password>", "Account password; only its scrypt digest is stored"
        ).action(lambda account_id, options=None: service.execute({
            "command": "account.create",
            "input": {
                "accountId": str(account_id),
                "password": options.get("password") if isinstance(options, Mapping) else None,
                "localConfirmation": bool(isinstance(options, Mapping) and options.get("confirmLocal") is True),
            },
        }))
        account.command("reset-password <accountId>").description("Reset password and revoke all refresh credentials; retain pairing keys").option(
            "--confirm-local", "Confirm this write on the local host"
        ).option("--password <password>", "New account password").action(lambda account_id, options=None: service.execute({
            "command": "account.reset-password", "input": {
                "accountId": str(account_id),
                "password": options.get("password") if isinstance(options, Mapping) else None,
                "localConfirmation": bool(isinstance(options, Mapping) and options.get("confirmLocal") is True),
            },
        }))
        account.command("status").description("Show Gateway account status").action(lambda: service.status())
        pairing = root.command("pairing").description("Manage Open Android Intelligence Gateway pairings")
        pairing.command("revoke <accountId> <deviceId>").description(
            "Revoke one device pairing: keys, credentials, grants, queue and unconfirmed attachments"
        ).option(
            "--confirm-local", "Confirm this write on the local host"
        ).action(lambda account_id, device_id, options=None: service.execute({
            "command": "pairing.revoke", "accountId": str(account_id), "deviceId": str(device_id),
            "localConfirmation": bool(isinstance(options, Mapping) and options.get("confirmLocal") is True),
        }))
        grant = root.command("grant").description("Manage Open Android Intelligence Gateway pairing grants")
        grant.command("bump <accountId> <deviceId>").description(
            "Raise one pairing's grantRevision after the Android-local grant changed"
        ).option(
            "--confirm-local", "Confirm this write on the local host"
        ).action(lambda account_id, device_id, options=None: service.execute({
            "command": "grant.bump", "accountId": str(account_id), "deviceId": str(device_id),
            "localConfirmation": bool(isinstance(options, Mapping) and options.get("confirmLocal") is True),
        }))
        account.command("delete <accountId>").description("Delete a Gateway account and all of its data").option(
            "--confirm-local", "Confirm this write on the local host"
        ).action(lambda account_id, options=None: service.execute({
            "command": "account.delete", "accountId": str(account_id),
            "localConfirmation": bool(isinstance(options, Mapping) and options.get("confirmLocal") is True),
        }))
    return registrar


# Parity aliases used by host adapters.
createAdminService = create_admin_service
createAdminPanel = create_admin_panel
createAdminCliRegistrar = create_admin_cli_registrar
isHostApiCompatible = is_host_api_compatible
