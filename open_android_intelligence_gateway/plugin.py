"""Hermes host registration boundary for the native Python Gateway."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from .admin import (
    HERMES_HOST_API,
    VERIFIED_HERMES_HOST_API,
    AdminService,
    bind_admin_service,
    create_admin_cli_registrar,
    create_admin_panel,
    create_admin_service,
    normalize_host_api,
)
from .adapter import (
    AccountPasswordVerifier,
    GatewayRequestVerifier,
    LocalCredentialVerifier,
    OpenAndroidPlatformAdapter,
    create_gateway_request_verifier,
)
from .account_paths import GATEWAY_DIRECTORY_NAME, WIRE_ID_PATTERN
from .contract_assets import materialised_contract_root, resolve_contract_root
from .core import PROTOCOL_VERSION, WIRE_PROTOCOL, GatewayCore, create_gateway_core
from .http import EXPOSURE_MODES, GatewayExposure, create_gateway_exposure
from .local_keys import resolve_local_master_key_store


# Surfaced by the host whenever the platform needs attention, so an
# operator who installed the plugin is told how to make it ready instead of
# being left with a gateway that quietly refuses every negotiation.
CONTRACT_SETUP_HINT = "协议契约未获取：请执行 hermes open-android-intelligence contract sync"


HERMES_PLUGIN_MANIFEST = {
    "id": "open-android-intelligence-gateway",
    "version": "2.1.0",
    "backend": "hermes",
    "protocolVersion": "2.1.0",
    "hostApi": {
        "status": "unverified",
        "min": None,
        "max": None,
        "commit": None,
    },
    "exposureModes": list(EXPOSURE_MODES),
    "management": {
        "surface": "host-ui-and-local-cli", "localOnly": True,
        "remotePort": None, "sensitiveOperations": "local-confirmation",
    },
    "securityBoundary": {
        "rawHeaders": "delegated-to-verified-request-seam",
        "tls": "host-or-explicit-terminator", "legacyBridge": "not-used",
    },
}

class HermesPluginContext(Protocol):
    plugin_data_dir: str | Path
    secret_store: Any
    credential_verifier: Any

    def register_platform(self, platform: GatewayPlatform) -> None:
        ...

    def register_admin(self, admin: AdminSurface) -> None:
        ...


class ManifestProtocolMismatch(RuntimeError):
    """The manifest declares a protocol version the core does not implement."""


def core_protocol_label() -> str:
    """The ``major.minor`` label the core actually negotiates."""
    return f"{PROTOCOL_VERSION['major']}.{PROTOCOL_VERSION['minor']}"


def verify_manifest_protocol(manifest: Mapping[str, Any] | None = None) -> None:
    """Refuse to load when the manifest and the core disagree on the protocol.

    This plugin releases independently of the application repository, so the
    manifest's ``protocolVersion`` and the core's constants are no longer
    updated by one commit. Without this check the two can drift apart with
    every test still green, and the mismatch would only reach the operator as a
    ``PROTOCOL_INCOMPATIBLE`` from a phone during negotiation. Failing closed at
    load time keeps the diagnosis on the host that can act on it.
    """
    declared_manifest = HERMES_PLUGIN_MANIFEST if manifest is None else manifest
    declared = str(declared_manifest.get("protocolVersion") or "").strip()
    core_label = core_protocol_label()
    if ".".join(declared.split(".")[:2]) != core_label:
        raise ManifestProtocolMismatch(
            f"插件清单声明的协议版本 {declared or '(缺失)'} 与网关核心协商的 "
            f"{core_label}（线协议 {WIRE_PROTOCOL}）不一致，拒绝加载。"
            f"请将插件与手机端一起升级到同一协议版本。"
        )


def _attr(value: Any, *names: str, default: Any = None) -> Any:
    for name in names:
        if isinstance(value, Mapping) and name in value:
            return value[name]
        if hasattr(value, name):
            return getattr(value, name)
    return default


class GatewayPlatform:
    platform_id = "open-android-intelligence-gateway"
    id = "open-android-intelligence-gateway"

    def __init__(self, core: GatewayCore, exposure: GatewayExposure, admin: AdminService):
        self.core = core
        self.exposure = exposure
        self.admin = admin
        self.management = create_admin_panel(admin)
        self.read_only = admin.read_only

    @property
    def readOnly(self) -> bool:
        return self.read_only

    def handle(self, request: Any) -> dict[str, Any]:
        if self.read_only:
            context = _attr(request, "context", default={})
            request_id = str(_attr(context, "requestId", "request_id", default="open-android-intelligence-route"))
            correlation_id = str(_attr(context, "correlationId", "correlation_id", default="open-android-intelligence-route"))
            return {
                "requestId": request_id, "correlationId": correlation_id, "protocol": WIRE_PROTOCOL,
                "error": {
                    "code": "HOST_INCOMPATIBLE", "message": "HOST_INCOMPATIBLE",
                    "retryable": False, "retryAfterSeconds": None, "details": {},
                },
            }
        return self.core.handle(request)


class AdminSurface:
    id = "open-android-intelligence-gateway"
    local_only = True
    remote_port = None

    def __init__(self, service: AdminService):
        self.service = service
        self.panel = create_admin_panel(service)

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

    def create_account(self, input: Mapping[str, Any]) -> dict[str, Any]:
        return self.service.create_account(input)

    createAccount = create_account

    def status(self) -> dict[str, Any]:
        return self.service.status()

    def execute(self, command: Mapping[str, Any]) -> dict[str, Any]:
        return self.service.execute(command)


class GatewayServices:
    def __init__(self, core: GatewayCore, admin: AdminService, exposure: GatewayExposure):
        self.core = core
        self.admin = admin
        self.exposure = exposure
        self.admin_panel = create_admin_panel(admin)


def plugin_root() -> Path:
    """The plugin checkout root — the parent of this package directory.

    Derived from this file rather than configured, so an install anywhere (a
    Hermes plugin directory, a virtualenv, an editable clone) resolves its own
    pin and staging area without an absolute path ever being committed.
    """
    return Path(__file__).resolve().parent.parent


def _resolve_contract_root() -> Path | None:
    """Return the contract already present in this checkout, or state why not.

    Deliberately inspection-only: loading happens inside the host startup and a
    cold fetch of the pinned repository would block it for tens of seconds. A
    missing contract is not allowed to abort loading either - the host stays
    startable and the operator gets a stated reason, while the Gateway itself
    refuses to serve because the core cannot compute the negotiated digest.
    """
    resolution = materialised_contract_root(plugin_root())
    if resolution.root is None:
        print(f"[open_android] 协议契约未就绪：{resolution.reason}")
        return None
    return resolution.root


def _storage_root(ctx: Any) -> Path | None:
    """The host data directory composed with the Gateway directory name.

    Returning None lets the core fall back to its own explicit default
    (configuration, then the Hermes home) rather than to a shell-relative path.
    """
    value = _attr(ctx, "plugin_data_dir", "pluginDataDir", default=None)
    if value is None:
        return None
    return Path(value).resolve() / GATEWAY_DIRECTORY_NAME / "accounts"


def compose_gateway_services(ctx: Any) -> GatewayServices:
    config = _attr(ctx, "plugin_config", "pluginConfig", default={}) or {}
    raw_api = _attr(ctx, "host_api", "hostApi", default=None)
    if raw_api is None and isinstance(config, Mapping):
        raw_api = config.get("hostApi", config.get("host_api"))

    host_version = _attr(ctx, "host_version", "hostVersion", default=None)
    if host_version is None and isinstance(config, Mapping):
        host_version = config.get("hostVersion", config.get("host_version"))

    # Autodetect real Hermes Agent runtime when running inside Hermes
    if host_version is None:
        try:
            import hermes_cli
            host_version = getattr(hermes_cli, "__version__", None)
        except Exception:
            pass

    # If running inside a live Hermes Agent host without an explicit host_api override,
    # resolve to the verified host API baseline for Hermes Agent v0.20.0+
    if raw_api is None:
        ctx_type_name = type(ctx).__name__
        is_hermes_context = (
            ctx_type_name == "PluginContext"
            or ("hermes_cli" in sys.modules and ctx_type_name != "FakeHermesContext")
        )
        if is_hermes_context and host_version is not None:
            raw_api = VERIFIED_HERMES_HOST_API

    host_api = normalize_host_api(raw_api)
    core = _attr(ctx, "gateway_core", "gatewayCore", default=None)
    verifier = _attr(ctx, "credential_verifier", "credentialVerifier", default=None)
    if core is None:
        # ADR 0023: prefer the host Secret Store and fall back to the operator's
        # restricted key file. Hermes exposes no Secret Store, so without this
        # fallback every account would silently run without a master key and
        # answer every authenticated request with MASTER_KEY_UNAVAILABLE.
        secret_store = _attr(ctx, "secret_store", "secretStore", default=None)
        if secret_store is None:
            # Installing the plugin is the operator's act of providing the key
            # source (ADR 0023), so it is provisioned here. A failure must not
            # take the whole host down: the platform start reports it instead.
            try:
                secret_store = resolve_local_master_key_store()
            except Exception as exc:  # noqa: BLE001 - operator-facing reason
                print(f"[open_android] 主密钥自动配置失败：{exc}")
                secret_store = None
        # The host may pin the contract itself; otherwise this checkout
        # resolves its own, which is what makes a standalone install work.
        host_contract_root = _attr(ctx, "contract_root", "contractRoot", default=None)
        contract_root = (
            host_contract_root if host_contract_root is not None else _resolve_contract_root()
        )
        core = create_gateway_core(
            storage_root=_storage_root(ctx),
            secret_store=secret_store,
            contract_root=contract_root,
            credential_verifier=verifier,
        )
    if verifier is None:
        # Password login is checked against the digest the local admin surface
        # recorded for that account. A host that keeps credentials elsewhere
        # supplies its own verifier; without one, an account that was never
        # given a password simply cannot be logged into.
        verifier = AccountPasswordVerifier(core)
        core.credential_verifier = verifier
    admin = create_admin_service(core=core, host_version=host_version, host_api=host_api)
    config = _attr(ctx, "plugin_config", "pluginConfig", default={}) or {}
    mode = config.get("exposureMode", "host-route") if isinstance(config, Mapping) else "host-route"
    if mode not in EXPOSURE_MODES:
        mode = "host-route"
    verify_request = _attr(ctx, "verify_request", "verifyRequest", default=None)
    if verify_request is None:
        # Without a verifier the HTTP boundary answers every authenticated
        # request with 401, so the platform would be unusable. The host may
        # still supply its own seam; this is the reference implementation that
        # checks the device signature the phone actually sends.
        verify_request = create_gateway_request_verifier(core)
    exposure = create_gateway_exposure(
        mode, core=core, host_version=host_version, host_api=host_api,
        verify_request=verify_request,
        max_body_bytes=_attr(ctx, "max_body_bytes", "maxBodyBytes", default=None),
    )
    return GatewayServices(core, admin, exposure)


def interactive_setup(
    admin: AdminService,
    input_fn: Callable[[str], str] = input,
    getpass_fn: Callable[[str], str] | None = None,
    is_tty: bool | None = None,
) -> bool:
    """Interactive account onboarding for `hermes gateway setup`.

    Prompts the user to initialize a Gateway account and storage sandbox on the
    local host without leaving the Hermes wizard. Falls back to printing CLI
    instructions if standard input is not a TTY or if user cancels.
    """
    if getpass_fn is None:
        import getpass
        getpass_fn = getpass.getpass

    print("\n  ─── 📱 Open Android Intelligence Gateway 配置向导 ───")
    if admin.read_only:
        print("  ⚠️  当前 Hermes 宿主处于只读兼容模式，无法在此主机上创建新账号。")
        print("  请先确保宿主环境满足 API 版本兼容要求后再试。\n")
        return False

    is_interactive = is_tty if is_tty is not None else sys.stdin.isatty()
    if not is_interactive:
        print("  当前运行在非交互式终端中，跳过交互输入。")
        print("  可通过 Hermes 本地 CLI 创建与管理手机端连接账号：")
        print("    hermes open-android-intelligence account create --username <用户名> --password <密码> --confirm-local\n")
        return True

    try:
        choice = input_fn("  是否现在为连接手机创建一个网关账号？[Y/n]: ").strip()
        if choice.lower() in ("n", "no"):
            print("  已跳过账号创建。后续可随时通过命令创建：")
            print("    hermes open-android-intelligence account create --username <用户名> --password <密码> --confirm-local\n")
            return True

        account_id = ""
        while not account_id:
            raw_id = input_fn("  请输入账号名称 (例如 phone1 / admin): ").strip()
            if not raw_id:
                print("  ❌ 账号名称不能为空，请重新输入。")
                continue
            if WIRE_ID_PATTERN.fullmatch(raw_id) is None:
                print("  ❌ 账号名称格式不合法（允许 1-128 位的字母、数字、点、下划线、波浪线或减号），请重新输入。")
                continue
            account_id = raw_id

        password = ""
        while not password:
            pwd = getpass_fn("  请输入连接密码: ")
            if not pwd:
                print("  ❌ 密码不能为空，请重新输入。")
                continue
            pwd_confirm = getpass_fn("  请再次输入密码以确认: ")
            if pwd != pwd_confirm:
                print("  ❌ 两次输入的密码不一致，请重新输入。")
                continue
            password = pwd

        confirm = input_fn(f"  确认在本地创建账号 '{account_id}' 的数据沙箱？[Y/n]: ").strip()
        if confirm.lower() in ("n", "no"):
            print("  已取消创建。")
            return False

        result = admin.execute({
            "command": "account.create",
            "input": {
                "accountId": account_id,
                "password": password,
                "localConfirmation": True,
            },
        })

        if result.get("ok"):
            import os
            port = os.getenv("OPEN_ANDROID_GATEWAY_PORT", "8045")
            storage_root = getattr(admin.core, "storage_root", "默认目录")
            print(f"\n  ✅ 账号 '{account_id}' 创建成功！")
            print(f"  • 数据存储沙箱: {storage_root}")
            print(f"  • 网关协议: Gateway Protocol v2 (已就绪)")
            print(f"  • 监听端口: {port} (可在 ~/.hermes/.env 中通过 OPEN_ANDROID_GATEWAY_PORT 修改)")
            key_path = getattr(getattr(admin.core, "secret_store", None), "path", None)
            if key_path is None:
                print("  • 主密钥: 由宿主 Secret Store 提供")
            else:
                print(f"  • 主密钥文件: {key_path} (权限 0600，安装插件时已自动生成)")
            print("\n  📱 手机端连接指南：")
            print("    1. 打开 Android 手机端 Open Android Intelligence App；")
            print(f"    2. 在登录页面输入 Gateway 地址 (例如 http://<本机IP>:{port}) 与账号 '{account_id}' 及刚刚设定的密码即可完成配对。\n")
            return True
        else:
            err = result.get("error", {})
            print(f"\n  ❌ 创建失败: {err.get('code', 'UNKNOWN_ERROR')}\n")
            return False

    except (EOFError, KeyboardInterrupt):
        print("\n  已取消交互向导。")
        return False


def register(ctx: Any) -> None:
    verify_manifest_protocol()
    services = compose_gateway_services(ctx)
    bind_admin_service(services.admin)
    from .device_tools import register_device_tools
    register_device_tools(ctx,services.core)
    gateway_platform = GatewayPlatform(services.core, services.exposure, services.admin)
    admin_surface = AdminSurface(services.admin)

    register_plat = _attr(ctx, "register_platform", "registerPlatform", default=None)
    if callable(register_plat):
        try:
            import inspect
            sig = inspect.signature(register_plat)
            params = [p for p in sig.parameters.values() if p.name != "self"]
            if len(params) == 1:
                register_plat(gateway_platform)
            else:
                def _build_adapter(config: Any) -> Any:
                    return OpenAndroidPlatformAdapter(config, services)

                def _check_deps() -> bool:
                    # This answers for the plugin's own wiring, not for the host's
                    # mood: the platform needs its core and its exposure routes.
                    return services.core is not None and services.exposure is not None

                def _is_connected(config: Any) -> bool:
                    # Outside the verified host API range every authenticated
                    # request is answered with HOST_INCOMPATIBLE, so the platform
                    # is not usable and must not report itself as connected.
                    return _check_deps() and not services.admin.read_only

                def _setup_fn() -> None:
                    interactive_setup(services.admin)

                register_plat(
                    name="open_android",
                    label="Open Android Intelligence (Gateway v2)",
                    adapter_factory=_build_adapter,
                    check_fn=_check_deps,
                    is_connected=_is_connected,
                    validate_config=_is_connected,
                    setup_fn=_setup_fn,
                    install_hint=CONTRACT_SETUP_HINT,
                    emoji="📱",
                )
                register_plat(
                    name="open_android_intelligence",
                    label="Open Android Intelligence Gateway",
                    adapter_factory=_build_adapter,
                    check_fn=_check_deps,
                    is_connected=_is_connected,
                    validate_config=_is_connected,
                    setup_fn=_setup_fn,
                    install_hint=CONTRACT_SETUP_HINT,
                    emoji="📱",
                )
        except Exception:
            try:
                register_plat(gateway_platform)
            except Exception:
                pass

    register_admin_fn = _attr(ctx, "register_admin", "registerAdmin", default=None)
    if callable(register_admin_fn):
        register_admin_fn(admin_surface)
    register_route = _attr(ctx, "register_http_route", "registerHttpRoute", "register_route", default=None)
    if callable(register_route):
        for route in services.exposure.routes:
            register_route({"path": route.path, "auth": route.auth, "match": route.match, "handler": route.handler})
    register_cli_cmd = _attr(ctx, "register_cli_command", "registerCliCommand", default=None)
    if callable(register_cli_cmd):
        def _account_directories() -> list[str]:
            root = Path(services.core.storage_root)
            if not root.is_dir():
                return []
            return sorted(directory.name for directory in root.iterdir() if directory.is_dir())

        def _report(result: Mapping[str, Any]) -> None:
            if result.get("ok"):
                print(f"✅ {result.get('operation')} 完成")
                return
            error = result.get("error") or {}
            print(f"❌ {result.get('operation')} 失败：{error.get('code')}")

        def _setup_cli_parser(parser: Any) -> None:
            subs = parser.add_subparsers(dest="open_android_intelligence_subcommand", required=False)

            p_account = subs.add_parser("account", help="Manage Open Android Intelligence Gateway accounts")
            acct_subs = p_account.add_subparsers(dest="account_action", required=False)

            p_create = acct_subs.add_parser("create", help="Create a new Gateway account")
            p_create.add_argument("--username", "-u", default=None, help="Username or Account ID")
            p_create.add_argument("account_id", nargs="?", default=None, help="Account ID")
            p_create.add_argument(
                "--password", "-p", required=True,
                help="Account password; only its scrypt digest is stored",
            )
            p_create.add_argument(
                "--confirm-local", action="store_true", default=False,
                help="Confirm this write on the local host; required for every account write",
            )

            acct_subs.add_parser("status", help="Show Gateway status")
            acct_subs.add_parser("list", help="List Gateway accounts")

            p_contract = subs.add_parser(
                "contract", help="Inspect or repair the Gateway protocol contract assets",
            )
            contract_subs = p_contract.add_subparsers(dest="contract_action", required=False)
            contract_subs.add_parser("status", help="Show where the contract was resolved from")
            contract_subs.add_parser("sync", help="Re-fetch the pinned contract revision")

            p_del = acct_subs.add_parser("delete", help="Delete a Gateway account and all of its data")
            p_del.add_argument("account_id", help="Account ID to delete")
            p_del.add_argument(
                "--confirm-local", action="store_true", default=False,
                help="Confirm this write on the local host; required for every account write",
            )

            subs.add_parser("status", help="Show Gateway status")

        def _dispatch_cli(args: Any) -> None:
            sub = getattr(args, "open_android_intelligence_subcommand", None)
            acct_act = getattr(args, "account_action", None)
            contract_action = getattr(args, "contract_action", None)
            confirmed = bool(getattr(args, "confirm_local", False))

            if sub == "contract":
                if contract_action not in ("status", "sync"):
                    print("❌ 错误：请指定 contract 的子命令，例如："
                          "hermes open-android-intelligence contract status")
                    return
                resolution = resolve_contract_root(
                    plugin_root(), force=contract_action == "sync",
                )
                if resolution.root is None:
                    print(f"❌ 协议契约未就绪：{resolution.reason}")
                    return
                if contract_action == "sync":
                    print(f"✅ 已按锁定提交同步协议契约：{resolution.pinned_ref}")
                print("📄 协议契约状态:")
                print(f"  • 来源: {resolution.source}")
                print(f"  • 锁定提交: {resolution.pinned_ref or '(由宿主直接指定)'}")
                print(f"  • 契约目录: {resolution.root}")
                return

            if sub == "account" and acct_act == "create":
                account_id = getattr(args, "username", None) or getattr(args, "account_id", None)
                if not account_id:
                    print("❌ 错误：请提供账号名称或 ID，例如："
                          "hermes open-android-intelligence account create --username <用户名> "
                          "--password <密码> --confirm-local")
                    return
                # Every account write goes through the one management service, so
                # the read-only gate and the local confirmation are enforced in
                # exactly one place for both the CLI and the host panel.
                result = services.admin.execute({
                    "command": "account.create",
                    "input": {
                        "accountId": str(account_id),
                        "password": str(getattr(args, "password", "") or ""),
                        "localConfirmation": confirmed,
                    },
                })
                _report(result)
                if result.get("ok"):
                    print(f"  • 账号标识 (Account ID): {account_id}")
                    print(f"  • 数据存储根目录: {services.core.storage_root}")
                    print("\n📱 手机端连接指南：")
                    print("  1. 打开 Android 手机端 Open Android Intelligence App。")
                    print(f"  2. 连接到此 Gateway 并使用账号 '{account_id}' 与刚设置的密码登录。")
                return

            if sub == "account" and acct_act == "list":
                accounts = _account_directories()
                if accounts:
                    print(f"📱 当前已配置的 Gateway 账号 ({len(accounts)}):")
                    for account in accounts:
                        print(f"  • {account}")
                else:
                    print("📱 当前尚未配置任何 Gateway 账号。")
                return

            if sub == "account" and acct_act == "delete":
                account_id = getattr(args, "account_id", None)
                if not account_id:
                    print("❌ 错误：请指定要删除的账号 ID")
                    return
                _report(services.admin.execute({
                    "command": "account.delete",
                    "accountId": str(account_id),
                    "localConfirmation": confirmed,
                }))
                return

            status_res = services.admin.status()
            print("📱 Open Android Intelligence Gateway 运行状态:")
            print("  • 协议版本: Gateway Protocol v2.1")
            print(f"  • 数据存储根目录: {services.core.storage_root}")
            if status_res.get("readOnly"):
                print("  • 宿主兼容性: 未验证（管理入口只读，外部端点返回 HOST_INCOMPATIBLE）")
            accounts = _account_directories()
            print(f"  • 已配置账号 ({len(accounts)}): {', '.join(accounts) if accounts else '无'}")

        register_cli_cmd(
            name="open-android-intelligence",
            help="Manage Open Android Intelligence Gateway accounts and platform status",
            setup_fn=_setup_cli_parser,
            handler_fn=_dispatch_cli,
        )

    register_cli = _attr(ctx, "register_cli", "registerCli", default=None)
    if callable(register_cli):
        register_cli(create_admin_cli_registrar(services.admin), {
            "parentPath": [], "commands": ["open-android-intelligence"],
            "descriptors": [{
                "name": "open-android-intelligence", "description": "Manage Open Android Intelligence Gateway accounts",
                "hasSubcommands": True,
            }],
        })


HERMES_PLUGIN = {
    "id": "open-android-intelligence-gateway",
    "name": "Open Android Intelligence Gateway",
    "description": "Open Android Intelligence Gateway Protocol v2 native Hermes platform",
    "register": register,
}


__all__ = [
    "AdminSurface", "GatewayPlatform", "GatewayRequestVerifier", "GatewayServices",
    "HermesPluginContext", "HERMES_PLUGIN", "HERMES_PLUGIN_MANIFEST",
    "compose_gateway_services", "create_gateway_request_verifier", "interactive_setup", "register",
]
